"""Version 2 reviews identify the full reconstructed batch, not just its counts."""

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_cli import store_export
from database.inventory_export_cli import export_inventory, review_record, main
from database.inventory_review_verify import verify_review

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples/osquery-system-info-expanded.json"


@unittest.skipUnless(os.name == "posix", "private inventory files require POSIX")
class InventoryReviewBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / "inventory.sqlite"
        store_export(FIXTURE, self.database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.inventory = export_inventory(self.database, export_data=FIXTURE.read_bytes())
        self.arguments = {"reviewed_at": "2026-10-23T05:00:00Z",
                          "reviewer_note": "Synthetic batch handoff."}

    def test_version_two_binds_and_verifies_without_publishing_identifiers(self):
        record = review_record(self.inventory, **self.arguments, bind_batch=True)
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(len(record["batch_sha256"]), 64)
        result = verify_review(self.database, json.dumps(record).encode(),
                               export_data=FIXTURE.read_bytes())
        self.assertTrue(result["batch_bound"])
        self.assertEqual(result["batch_sha256"], record["batch_sha256"])
        self.assertNotIn("checkout.example.test", json.dumps(record))
        self.assertEqual(record, review_record(self.inventory, **self.arguments, bind_batch=True))

    def test_equal_counts_on_different_inventory_fail_for_bound_review(self):
        source = self.root / "different.json"
        rows = json.loads(FIXTURE.read_bytes())
        rows[0]["hostname"] = "other.example.test"
        source.write_text(json.dumps(rows))
        database = self.root / "different.sqlite"
        store_export(source, database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        record = review_record(self.inventory, **self.arguments, bind_batch=True)
        with self.assertRaises(ValueError):
            verify_review(database, json.dumps(record).encode(), export_data=source.read_bytes())
        legacy = review_record(self.inventory, **self.arguments)
        self.assertEqual(legacy["schema_version"], 1)
        self.assertNotIn("batch_sha256", legacy)
        self.assertEqual(verify_review(database, json.dumps(legacy).encode(),
                                      export_data=source.read_bytes())["status"], "consistent")
        with self.assertRaises(ValueError):
            verify_review(self.database, json.dumps(legacy).encode(),
                           export_data=FIXTURE.read_bytes(), require_batch_binding=True)

    def test_changed_batch_digest_and_schema_fail(self):
        record = review_record(self.inventory, **self.arguments, bind_batch=True)
        for field, value in (("batch_sha256", "0" * 64), ("schema_version", True),
                             ("schema_version", 3)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_review(self.database, json.dumps(dict(record, **{field: value})).encode(),
                               export_data=FIXTURE.read_bytes())

    def test_cli_requires_review_format_and_produces_version_two(self):
        stdout = StringIO()
        arguments = [str(self.database), "--export", str(FIXTURE), "--bind-batch"]
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(main(arguments), 2)
        self.assertEqual(stdout.getvalue(), "")
        with redirect_stdout(stdout):
            self.assertEqual(main(arguments + ["--format", "review", "--reviewed-at",
                self.arguments["reviewed_at"], "--reviewer-note", self.arguments["reviewer_note"]]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["schema_version"], 2)


if __name__ == "__main__":
    unittest.main()
