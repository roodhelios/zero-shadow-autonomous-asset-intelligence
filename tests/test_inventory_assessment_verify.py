import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_assessment_cli import retain_assessment
from database.inventory_assessment_verify import main, verify_assessment
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/"examples/osquery-system-info-expanded.json"
FINDINGS = ROOT/"examples/inventory-findings.jsonl"
DIRECTORY = ROOT/"examples/ownership-directory.json"


@unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
class AssessmentVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory, self.assessed = self.root/"inventory.sqlite", self.root/"assessed.sqlite"
        store_export(EXPORT, self.inventory, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))

    def retain(self, *, check_source=True):
        retain_assessment(self.inventory, FINDINGS.read_bytes(), DIRECTORY.read_bytes(), self.assessed,
            as_of=date(2026, 10, 23), assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc),
            export_data=EXPORT.read_bytes() if check_source else None)

    def verify(self):
        return verify_assessment(self.assessed, EXPORT.read_bytes())

    def test_complete_native_reproduction_preserves_source_database(self):
        self.retain(); original = self.assessed.read_bytes()
        result = self.verify()
        self.assertEqual(result["status"], "assessment_reproduced")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["asset_count"], 2)
        self.assertTrue(result["original_export_checked"])
        self.assertEqual(self.assessed.read_bytes(), original)

    def test_original_export_is_checked_even_when_initial_retention_did_not_check_it(self):
        self.retain(check_source=False)
        self.assertTrue(self.verify()["original_export_checked"])
        with self.assertRaises(ValueError):
            verify_assessment(self.assessed, EXPORT.read_bytes()+b"\n")

    def test_stored_plan_change_fails_despite_unchanged_retained_input_hashes(self):
        self.retain()
        with sqlite3.connect(self.assessed) as connection:
            connection.execute("DROP TRIGGER remediation_plans_no_update")
            connection.execute("UPDATE remediation_plans SET priority='P3'")
        with self.assertRaises(ValueError):
            self.verify()

    def test_edited_input_with_recomputed_hash_still_must_match_stored_decisions(self):
        self.retain()
        record = json.loads(FINDINGS.read_bytes()); record["asset_tags"] = {}
        changed = json.dumps(record)+"\n"
        with sqlite3.connect(self.assessed) as connection:
            connection.execute("DROP TRIGGER assessment_input_no_update")
            digests = json.loads(connection.execute("SELECT input_sha256_json FROM inventory_assessment_input").fetchone()[0])
            digests["findings"] = hashlib.sha256(changed.encode()).hexdigest()
            connection.execute("UPDATE inventory_assessment_input SET findings_jsonl=?, input_sha256_json=?",
                               (changed, json.dumps(digests)))
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_metadata_sidecars_symlinks_and_invalid_cli_emit_no_success(self):
        with self.assertRaises(sqlite3.DatabaseError):
            verify_assessment(self.inventory, EXPORT.read_bytes())
        self.retain()
        sidecar = Path(str(self.assessed)+"-wal"); sidecar.write_bytes(b"synthetic")
        with self.assertRaises(ValueError):
            self.verify()
        sidecar.unlink()
        link = self.root/"link.sqlite"; link.symlink_to(self.assessed)
        with self.assertRaises(OSError):
            verify_assessment(link, EXPORT.read_bytes())
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main([str(link), "--export", str(EXPORT)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(str(link), stderr.getvalue())
        with sqlite3.connect(self.assessed) as connection:
            connection.execute("CREATE VIEW unsupported_extra_view AS SELECT 1 AS fixture")
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
