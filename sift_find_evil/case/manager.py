"""Manager for case lifecycle and evidence tracking."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from .models import Case, CaseStatus, EvidenceFile


class CaseManager:
    """Manages forensic investigation cases."""

    def __init__(self, case_root: Path = Path("/cases")):
        """Initialize case manager.

        Args:
            case_root: Root directory for all cases (default: /cases)
        """
        self.case_root = case_root

    def create_case(
        self,
        case_id: str,
        name: str,
        examiner: str,
        description: Optional[str] = None,
    ) -> Case:
        """Create a new case with directory structure.

        Args:
            case_id: Unique case identifier (e.g., INC-2026-001)
            name: Human-readable case name
            examiner: Name of primary examiner
            description: Optional case description

        Returns:
            Created Case object
        """
        case_dir = self.case_root / case_id

        if case_dir.exists():
            raise ValueError(f"Case directory already exists: {case_dir}")

        # Create directory structure
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "analysis").mkdir(exist_ok=True)
        (case_dir / "reports").mkdir(exist_ok=True)
        (case_dir / "exports").mkdir(exist_ok=True)

        # Create case metadata
        case = Case(
            case_id=case_id,
            name=name,
            examiner=examiner,
            created_at=datetime.utcnow(),
            status=CaseStatus.OPEN,
            directory=case_dir,
            description=description,
        )

        # Save CASE.yaml
        self._save_case_metadata(case)

        # Initialize empty evidence registry
        evidence_path = case_dir / "evidence.json"
        with open(evidence_path, "w") as f:
            json.dump({"evidence": []}, f, indent=2)

        # Initialize empty audit log
        audit_path = case_dir / "audit.jsonl"
        audit_path.touch()

        return case

    def load_case(self, case_id: str) -> Case:
        """Load case metadata.

        Args:
            case_id: Case identifier

        Returns:
            Case object
        """
        case_dir = self.case_root / case_id
        case_file = case_dir / "CASE.yaml"

        if not case_file.exists():
            raise FileNotFoundError(f"Case metadata not found: {case_file}")

        with open(case_file, "r") as f:
            data = yaml.safe_load(f)

        return Case.from_dict(data)

    def register_evidence(
        self,
        case_id: str,
        file_path: Path,
        description: str,
        evidence_type: Optional[str] = None,
    ) -> EvidenceFile:
        """Register evidence file with SHA-256 hash.

        Args:
            case_id: Case identifier
            file_path: Path to evidence file
            description: Description of evidence
            evidence_type: Optional evidence type (disk_image, memory_dump, etc.)

        Returns:
            EvidenceFile object
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        # Calculate SHA-256 hash
        sha256_hash = self._calculate_sha256(file_path)
        file_size = file_path.stat().st_size

        evidence = EvidenceFile(
            file_path=file_path,
            description=description,
            sha256_hash=sha256_hash,
            file_size=file_size,
            evidence_type=evidence_type,
        )

        # Load existing evidence registry
        case_dir = self.case_root / case_id
        evidence_path = case_dir / "evidence.json"

        if evidence_path.exists():
            with open(evidence_path, "r") as f:
                data = json.load(f)
        else:
            data = {"evidence": []}

        # Append new evidence
        data["evidence"].append(evidence.to_dict())

        # Save updated registry
        with open(evidence_path, "w") as f:
            json.dump(data, f, indent=2)

        return evidence

    def verify_evidence(self, case_id: str) -> dict:
        """Verify all registered evidence hashes.

        Args:
            case_id: Case identifier

        Returns:
            Dictionary with verification results
        """
        case_dir = self.case_root / case_id
        evidence_path = case_dir / "evidence.json"

        if not evidence_path.exists():
            return {"error": "No evidence registry found"}

        with open(evidence_path, "r") as f:
            data = json.load(f)

        results = {
            "total": len(data["evidence"]),
            "verified": 0,
            "failed": 0,
            "missing": 0,
            "details": [],
        }

        for item in data["evidence"]:
            evidence = EvidenceFile.from_dict(item)
            file_path = evidence.file_path

            if not file_path.exists():
                results["missing"] += 1
                results["details"].append({
                    "file": str(file_path),
                    "status": "MISSING",
                    "registered_hash": evidence.sha256_hash,
                })
                continue

            current_hash = self._calculate_sha256(file_path)
            if current_hash == evidence.sha256_hash:
                results["verified"] += 1
                results["details"].append({
                    "file": str(file_path),
                    "status": "VERIFIED",
                    "hash": current_hash,
                })
            else:
                results["failed"] += 1
                results["details"].append({
                    "file": str(file_path),
                    "status": "FAILED",
                    "registered_hash": evidence.sha256_hash,
                    "current_hash": current_hash,
                })

        return results

    def get_case_status(self, case_id: str) -> dict:
        """Get case status summary.

        Args:
            case_id: Case identifier

        Returns:
            Dictionary with case status information
        """
        case = self.load_case(case_id)
        case_dir = self.case_root / case_id

        # Count evidence files
        evidence_path = case_dir / "evidence.json"
        evidence_count = 0
        if evidence_path.exists():
            with open(evidence_path, "r") as f:
                data = json.load(f)
                evidence_count = len(data.get("evidence", []))

        # Count findings
        findings_path = case_dir / "findings.json"
        findings_count = 0
        if findings_path.exists():
            with open(findings_path, "r") as f:
                data = json.load(f)
                findings_count = data.get("summary", {}).get("total", 0)

        # Count audit entries
        audit_path = case_dir / "audit.jsonl"
        audit_count = 0
        if audit_path.exists():
            with open(audit_path, "r") as f:
                audit_count = sum(1 for _ in f)

        return {
            "case_id": case.case_id,
            "name": case.name,
            "status": case.status.value,
            "examiner": case.examiner,
            "created_at": case.created_at.isoformat(),
            "directory": str(case.directory),
            "evidence_count": evidence_count,
            "findings_count": findings_count,
            "audit_entries": audit_count,
        }

    def _save_case_metadata(self, case: Case) -> None:
        """Save case metadata to CASE.yaml."""
        case_file = case.directory / "CASE.yaml"
        with open(case_file, "w") as f:
            yaml.dump(case.to_dict(), f, default_flow_style=False, sort_keys=False)

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
