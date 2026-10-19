"""Compare complete discovery batches without inferring physical deletion or risk."""

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_cli import store_export
from database.inventory_diff_cli import main

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "inventory publication requires POSIX")
class InventoryDiffTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.make("base", ROOT / "examples/osquery-system-info.json", 19)

    def make(self, name, source, day, scope="synthetic"):
        path = self.root / (name + ".sqlite")
        store_export(source, path, scope=scope, observed_at=datetime(2026, 10, day, tzinfo=timezone.utc))
        return path

    def compare(self, current):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(self.base), str(current)]), 0)
        return json.loads(output.getvalue())

    def test_added_claim_and_shared_identity_are_reported_read_only(self):
        current = self.make("expanded", ROOT / "examples/osquery-system-info-expanded.json", 20)
        before = [path.read_bytes() for path in (self.base, current)]
        result = self.compare(current)
        self.assertEqual(result["counts"], {"base_assets": 1, "current_assets": 2,
            "added": 1, "not_observed": 0, "shared": 1, "changed_shared": 0})
        self.assertTrue(result["source_bytes_changed"])
        self.assertNotIn("risk_score", result)
        self.assertEqual(before, [path.read_bytes() for path in (self.base, current)])

    def test_later_observation_does_not_count_as_changed_identity(self):
        current = self.make("same", ROOT / "examples/osquery-system-info.json", 20)
        result = self.compare(current)
        self.assertEqual(result["changed_shared_asset_ids"], [])
        self.assertFalse(result["source_bytes_changed"])

    def test_formatting_changes_are_separate_from_identity_changes(self):
        source = self.root / "formatted.json"
        source.write_bytes((ROOT / "examples/osquery-system-info.json").read_bytes() + b"\n")
        current = self.make("formatted", source, 20)
        result = self.compare(current)
        self.assertTrue(result["source_bytes_changed"])
        self.assertEqual(result["changed_shared_asset_ids"], [])
        self.assertEqual(result["added_asset_ids"], [])

    def test_changed_shared_metadata_is_visible(self):
        current = self.make("metadata", ROOT / "examples/osquery-system-info.json", 20)
        with sqlite3.connect(current) as connection:
            connection.execute("UPDATE assets SET primary_hostname='changed.example.test'")
        result = self.compare(current)
        self.assertEqual(result["counts"]["changed_shared"], 1)

    def test_absence_is_reported_without_claiming_deletion(self):
        old = self.make("old-expanded", ROOT / "examples/osquery-system-info-expanded.json", 18)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(old), str(self.base)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["counts"]["not_observed"], 1)
        self.assertNotIn("deleted_assets", result)

    def test_incompatible_scope_old_time_and_bad_receipt_fail(self):
        targets = [self.make("owned", ROOT / "examples/osquery-system-info.json", 20, "owned"),
                   self.make("old", ROOT / "examples/osquery-system-info.json", 18)]
        corrupt = self.make("corrupt", ROOT / "examples/osquery-system-info.json", 20)
        with sqlite3.connect(corrupt) as connection:
            connection.execute("DROP TABLE inventory_import_receipt")
        for target in [*targets, corrupt]:
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                self.assertEqual(main([str(self.base), str(target)]), 2)
            self.assertEqual(output.getvalue(), "")

    def test_output_is_private_and_exclusive(self):
        path = self.root / "changes.json"
        args = [str(self.base), str(self.base), "--output", str(path)]
        self.assertEqual(main(args), 0)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        with redirect_stderr(StringIO()):
            self.assertEqual(main(args), 2)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
