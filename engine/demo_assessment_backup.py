"""Restore a verified synthetic assessment after removing its original database."""

import hashlib
import json
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from database.assessment_backup import backup_assessment, restore_assessment
from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def exercise():
    export_path = EXAMPLES / "osquery-system-info-expanded.json"
    export = export_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="assessment-backup-demo-") as directory:
        root = Path(directory)
        for name in ("source", "backups", "recovered"):
            (root / name).mkdir(mode=0o700)
        discovery, original = root / "source/discovery.sqlite", root / "source/assessed.sqlite"
        backup, restored = root / "backups/assessment.sqlite", root / "recovered/assessment.sqlite"
        store_export(export_path, discovery, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        retain_assessment(discovery, (EXAMPLES / "inventory-findings.jsonl").read_bytes(),
                          (EXAMPLES / "ownership-directory.json").read_bytes(), original,
                          as_of=date(2026, 10, 23),
                          assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc), export_data=export)
        before = original.read_bytes()
        receipt = backup_assessment(original, backup, export_data=export)
        if original.read_bytes() != before or backup.read_bytes() != before:
            raise ValueError("backup changed original assessment bytes")
        digest = receipt["database_sha256"]
        original.unlink()
        discovery.unlink()
        result = restore_assessment(backup, restored, export_data=export, expected_sha256=digest)
        if restored.read_bytes() != before or backup.read_bytes() != before:
            raise ValueError("restore did not preserve exact backup bytes")
        damaged = root / "backups/changed.sqlite"
        damaged.write_bytes(before + b"changed")
        damaged.chmod(0o600)
        cases = ((backup, export, "0" * 64),
                 (backup, export + b"\n", digest), (damaged, export, digest))
        for index, (source, data, pin) in enumerate(cases):
            rejected = root / "recovered" / (str(index) + ".sqlite")
            try:
                restore_assessment(source, rejected, export_data=data, expected_sha256=pin)
            except ValueError:
                if rejected.exists():
                    raise ValueError("failed restore published an artifact")
            else:
                raise ValueError("invalid restore accepted")
        if hashlib.sha256(restored.read_bytes()).hexdigest() != digest:
            raise ValueError("restored digest changed")
    return {"status": "assessment_backup_exercise_passed", "scope": "synthetic",
            "asset_count": result["asset_count"], "finding_count": result["finding_count"],
            "assessment_status": result["assessment_status"], "model_status": result["model_status"],
            "original_databases_removed": True, "exact_bytes_restored": True,
            "negative_cases_rejected": len(cases), "backup_unchanged": True,
            "interpretation": "Temporary native SQLite copies with fixed fixture dates. "
            "No power-loss, remote backup, source-authentication or retention-policy validation."}


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print("error: local assessment backup exercise failed", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
