"""A retained inventory export includes the complete reconciled batch, not one host."""

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_cli import store_export
from database.inventory_export_cli import export_inventory, main

FIXTURE = Path(__file__).resolve().parents[1] / "examples/osquery-system-info-expanded.json"


@unittest.skipUnless(os.name == "posix", "private inventory publication requires POSIX")
class InventoryExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "inventory.sqlite"
        self.receipt = store_export(FIXTURE, self.path, scope="synthetic",
                                   observed_at=datetime(2026, 10, 20, tzinfo=timezone.utc))

    def test_exports_every_asset_deterministically_without_writing_database(self):
        before = self.path.read_bytes()
        result = export_inventory(self.path, export_data=FIXTURE.read_bytes())
        self.assertEqual(result, export_inventory(self.path, export_data=FIXTURE.read_bytes()))
        self.assertEqual((result["asset_count"], result["observation_count"]), (2, 2))
        self.assertEqual([item["asset"]["asset_id"] for item in result["assets"]],
                         self.receipt["asset_ids"])
        self.assertTrue(result["import_reconciliation"]["original_export_checked"])
        for asset in result["assets"]:
            self.assertEqual(len(asset["observations"]), 1)
            self.assertEqual(asset["observations"][0]["scope"], "synthetic")
            self.assertEqual(asset["findings"], [])
            self.assertEqual(asset["ownership_decisions"], [])
            self.assertEqual(asset["remediation_plans"], [])
            self.assertEqual(len(asset["snapshot_sha256"]), 64)
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_private_output_and_no_overwrite(self):
        output = self.path.with_suffix(".json")
        with redirect_stdout(StringIO()):
            self.assertEqual(main([str(self.path), "--export", str(FIXTURE),
                                   "--output", str(output)]), 0)
        before = output.read_bytes()
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(before)["asset_count"], 2)
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            self.assertEqual(main([str(self.path), "--output", str(output)]), 2)
            self.assertEqual(main([str(self.path), "--output", str(self.path)]), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_stdout_without_original_is_explicitly_unchecked(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(self.path)]), 0)
        self.assertFalse(json.loads(output.getvalue())["import_reconciliation"]["original_export_checked"])

    def test_source_mismatch_receipt_corruption_and_missing_receipt_publish_nothing(self):
        wrong = self.path.with_suffix(".source.json")
        wrong.write_bytes(FIXTURE.read_bytes() + b"\n")
        self.assert_failure(["--export", str(wrong)])
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TRIGGER inventory_receipt_no_update")
            connection.execute("UPDATE inventory_import_receipt SET receipt_sha256='invalid'")
        self.assert_failure([])
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE inventory_import_receipt")
        self.assert_failure([])

    def test_changed_payload_is_rejected_when_original_supplied(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TRIGGER asset_observations_no_update")
            connection.execute("UPDATE asset_observations SET payload_json=replace(payload_json, 'checkout', 'modified')")
        self.assert_failure(["--export", str(FIXTURE)])

    def test_symlink_and_non_database_fail_without_echoing_data(self):
        link = self.path.with_suffix(".link")
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            export_inventory(link)
        self.path.write_text("synthetic-private-marker")
        self.assert_failure([])

    def assert_failure(self, extra):
        output = self.path.with_suffix(".failed.json")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main([str(self.path), "--output", str(output), *extra]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(output.exists())
        self.assertNotIn("synthetic-private-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
