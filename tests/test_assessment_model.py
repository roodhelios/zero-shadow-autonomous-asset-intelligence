import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from database.assessment_model import current_contract
from database.inventory_assessment_cli import retain_assessment
from database.inventory_assessment_verify import verify_assessment
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/"examples/osquery-system-info-expanded.json"


@unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
class AssessmentModelTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); inventory = root/"inventory.sqlite"
        self.assessed = root/"assessed.sqlite"
        store_export(EXPORT, inventory, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.result = retain_assessment(inventory, (ROOT/"examples/inventory-findings.jsonl").read_bytes(),
            (ROOT/"examples/ownership-directory.json").read_bytes(), self.assessed,
            as_of=date(2026, 10, 23), assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc))

    def verify(self, **options):
        return verify_assessment(self.assessed, EXPORT.read_bytes(), **options)

    def test_new_retention_records_current_model_and_reproduces_without_mutating_source(self):
        before = self.assessed.read_bytes()
        result = self.verify(require_model_binding=True)
        self.assertEqual(result["model_binding"], self.result["model_binding"])
        self.assertEqual(result["model_binding"]["model_version"], 1)
        self.assertEqual(result["model_binding"]["status"], "bound_current_model")
        self.assertEqual(self.assessed.read_bytes(), before)
        with sqlite3.connect(self.assessed) as connection:
            for statement in ("DELETE FROM inventory_assessment_model",
                              "UPDATE inventory_assessment_model SET binding_sha256='changed'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)

    def test_legacy_data_has_explicit_unversioned_status_and_strict_mode_rejects_it(self):
        with sqlite3.connect(self.assessed) as connection:
            connection.execute("DROP TABLE inventory_assessment_model")
        self.assertEqual(self.verify()["model_binding"]["status"], "legacy_unversioned")
        with self.assertRaises(ValueError):
            self.verify(require_model_binding=True)

    def test_changed_current_implementation_rejects_bound_data_without_silent_fallback(self):
        changed = current_contract()
        changed["implementation_sha256"]["engine/risk.py"] = "0"*64
        with patch("database.assessment_model.current_contract", return_value=changed):
            with self.assertRaises(ValueError):
                self.verify()

    def test_unknown_version_corrupt_hash_and_boolean_version_fail(self):
        original = current_contract()
        for value, recompute in [(dict(original, model_version=2), True),
                                 (dict(original, model_version=True), True), (original, False)]:
            with sqlite3.connect(self.assessed) as connection:
                connection.execute("DROP TRIGGER IF EXISTS assessment_model_no_update")
                payload = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
                digest = hashlib.sha256(payload.encode()).hexdigest() if recompute else "0"*64
                connection.execute("UPDATE inventory_assessment_model SET contract_json=?, binding_sha256=?",
                                   (payload, digest))
            with self.assertRaises(ValueError):
                self.verify()


if __name__ == "__main__":
    unittest.main()
