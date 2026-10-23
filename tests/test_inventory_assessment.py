import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.inventory_assessment_cli import main, retain_assessment
from database.inventory_cli import store_export
from database.inventory_export_cli import export_inventory
from database.repository import EvidenceRepository

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "examples/osquery-system-info-expanded.json"
FINDINGS = ROOT / "examples/inventory-findings.jsonl"
DIRECTORY = ROOT / "examples/ownership-directory.json"


@unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
class InventoryAssessmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database, self.output = self.root/"inventory.sqlite", self.root/"assessment.sqlite"
        store_export(EXPORT, self.database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))

    def retain(self, rows=None, **options):
        return retain_assessment(self.database, FINDINGS.read_bytes() if rows is None else rows,
            DIRECTORY.read_bytes(), self.output, as_of=date(2026, 10, 23),
            assessed_at=options.get("assessed_at", datetime(2026, 10, 23, 1, tzinfo=timezone.utc)),
            export_data=EXPORT.read_bytes())

    def test_native_sqlite_retains_linked_decisions_and_inputs_without_changing_original(self):
        before = self.database.read_bytes()
        self.assertEqual(self.retain()["finding_count"], 1)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        result = export_inventory(self.output, export_data=EXPORT.read_bytes())
        assessed = [asset for asset in result["assets"] if asset["findings"]]
        self.assertEqual(len(assessed), 1)
        self.assertEqual(assessed[0]["remediation_plans"][0]["priority"], "P0")
        self.assertEqual(assessed[0]["ownership_decisions"][0]["team_id"], "cloud-platform")
        self.assertEqual(assessed[0]["findings"][0]["observed_at"], "2026-10-23T01:00:00Z")
        with sqlite3.connect(self.output) as connection:
            row = connection.execute("SELECT findings_jsonl, ownership_directory_json, as_of "
                                     "FROM inventory_assessment_input").fetchone()
            self.assertEqual(row, (FINDINGS.read_text(), DIRECTORY.read_text(), "2026-10-23"))
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            for table in ("findings", "ownership_decisions", "remediation_plans", "inventory_assessment_input"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("DELETE FROM " + table)

    def test_unknown_duplicate_empty_invalid_and_earlier_assessment_never_publish(self):
        row = json.loads(FINDINGS.read_bytes()); row["finding"]["asset_id"] = "not-retained"
        for data in (b"", FINDINGS.read_bytes()*2, json.dumps(row).encode(), FINDINGS.read_bytes()+b"invalid"):
            with self.assertRaises(ValueError):
                self.retain(data)
            self.assertFalse(self.output.exists())
        with self.assertRaises(ValueError):
            self.retain(assessed_at=datetime(2026, 10, 22, tzinfo=timezone.utc))

    def test_no_overwrite_and_no_second_assessment_in_existing_lineage(self):
        self.retain(); before = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            self.retain()
        self.assertEqual(self.output.read_bytes(), before)
        self.database = self.output; self.output = self.root/"second.sqlite"
        with self.assertRaises(ValueError):
            self.retain()
        self.assertFalse(self.output.exists())

    def test_middle_write_failure_rolls_back_all_decisions_and_never_publishes(self):
        row = json.loads(FINDINGS.read_bytes()); row["finding"]["finding_id"] = "second-finding"
        rows = FINDINGS.read_bytes() + json.dumps(row).encode() + b"\n"
        original = EvidenceRepository._store_decisions
        calls = []

        def fail_second(repository, bundle, **options):
            calls.append(bundle)
            if len(calls) == 2:
                raise sqlite3.IntegrityError("synthetic failure")
            original(repository, bundle, **options)

        observed_counts = []
        method = EvidenceRepository.store_assessments

        def inspect_rollback(repository, bundles):
            try:
                method(repository, bundles)
            except sqlite3.IntegrityError:
                observed_counts.extend(repository.connection.execute("SELECT count(*) FROM " + table).fetchone()[0]
                    for table in ("findings", "ownership_decisions", "remediation_plans"))
                raise

        with patch.object(EvidenceRepository, "_store_decisions", fail_second), \
             patch.object(EvidenceRepository, "store_assessments", inspect_rollback):
            with self.assertRaises(sqlite3.IntegrityError):
                self.retain(rows)
        self.assertEqual(observed_counts, [0, 0, 0])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".assessment-*")), [])

    def test_cli_success_and_fixed_error_exclude_input_values(self):
        args = [str(self.database), str(FINDINGS), "--directory", str(DIRECTORY),
                "--as-of", "2026-10-23", "--assessed-at", "2026-10-23T01:00:00Z",
                "--output", str(self.output)]
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(args), 0)
        with redirect_stderr(stderr):
            self.assertEqual(main(args), 2)
        self.assertNotIn(str(self.output), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
