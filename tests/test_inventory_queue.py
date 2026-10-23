import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.inventory_cli import store_export
from engine.inventory_queue_cli import plan_inventory, main
from engine.work_queue_cli import build_from_jsonl

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "examples/osquery-system-info-expanded.json"
FINDINGS = ROOT / "examples/inventory-findings.jsonl"
DIRECTORY = ROOT / "examples/ownership-directory.json"
AS_OF = date(2026, 10, 23)


@unittest.skipUnless(os.name == "posix", "private inventories require POSIX")
class InventoryQueueTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.database = self.root / "inventory.sqlite"
        store_export(EXPORT, self.database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.rows = FINDINGS.read_bytes()

    def plan(self, data=None, **options):
        return plan_inventory(self.database, self.rows if data is None else data,
            DIRECTORY.read_bytes(), as_of=AS_OF, **options)

    def test_inventory_linked_queue_matches_existing_planner_without_writing_database(self):
        before = self.database.read_bytes()
        result = self.plan(export_data=EXPORT.read_bytes())
        binding = result["inventory_binding"]
        self.assertEqual(binding["asset_count"], 2)
        self.assertEqual(binding["assets_with_supplied_findings"], 1)
        self.assertEqual(binding["assets_without_supplied_findings"], 1)
        self.assertTrue(binding["original_export_checked"])
        self.assertEqual(result["queues"], build_from_jsonl(FINDINGS,
            directory_path=DIRECTORY, as_of=AS_OF))
        self.assertEqual(result["queues"]["assigned_item_count"], 1)
        self.assertEqual(self.database.read_bytes(), before)

    def test_unknown_asset_and_duplicate_finding_ids_fail(self):
        row = json.loads(self.rows)
        row["finding"]["asset_id"] = "asset-not-in-inventory"
        with self.assertRaises(ValueError):
            self.plan(json.dumps(row).encode())
        with self.assertRaises(ValueError):
            self.plan(self.rows + self.rows)

    def test_empty_findings_leave_all_assets_unassessed(self):
        result = self.plan(b"\n")
        self.assertEqual(result["inventory_binding"]["assets_without_supplied_findings"], 2)
        self.assertEqual(result["queues"]["assigned_item_count"], 0)
        self.assertEqual(result["queues"]["unassigned_item_count"], 0)

    def test_multiple_findings_for_same_asset_do_not_inflate_coverage(self):
        row = json.loads(self.rows)
        row["finding"]["finding_id"] = "second-synthetic-finding"
        result = self.plan(self.rows + json.dumps(row).encode() + b"\n")
        self.assertEqual(result["queues"]["assigned_item_count"], 2)
        self.assertEqual(result["inventory_binding"]["assets_with_supplied_findings"], 1)

    def test_assessment_and_inventory_changes_are_visible(self):
        base = self.plan()
        row = json.loads(self.rows); row["asset_tags"] = {}
        changed = self.plan(json.dumps(row).encode())
        self.assertEqual(changed["queues"]["unassigned_item_count"], 1)
        self.assertNotEqual(changed["input_sha256"]["findings"], base["input_sha256"]["findings"])
        self.assertEqual(changed["inventory_binding"]["batch_sha256"], base["inventory_binding"]["batch_sha256"])
        with self.assertRaises(ValueError):
            self.plan(export_data=EXPORT.read_bytes()+b"\n")

    def test_invalid_tail_duplicate_fields_unknown_fields_and_bounds_fail(self):
        row = json.loads(self.rows)
        bad = [self.rows+b"private-fixture-marker", self.rows+b'{"finding":{},"finding":{}}',
               json.dumps(dict(row, unknown="private-fixture-marker")).encode()]
        for data in bad:
            with self.assertRaises(ValueError):
                self.plan(data)
        for name in ("MAX_BYTES", "MAX_LINE_BYTES", "MAX_RECORDS"):
            with patch("engine.inventory_queue_cli."+name, 0), self.assertRaises(ValueError):
                self.plan()

    def test_cli_private_output_and_failures_preserve_existing_evidence(self):
        output = self.root / "queue.json"
        args = [str(self.database), str(FINDINGS), "--directory", str(DIRECTORY),
                "--as-of", AS_OF.isoformat(), "--export", str(EXPORT), "--output", str(output)]
        self.assertEqual(main(args), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(args), 2)
        self.assertEqual(output.read_bytes(), before)
        bad = self.root / "bad.jsonl"; bad.write_text('private-fixture-marker')
        args[1] = str(bad); args[-1] = str(self.root / 'failed.json')
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(args), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn('private-fixture-marker', stderr.getvalue())
        self.assertFalse((self.root/'failed.json').exists())


if __name__ == "__main__":
    unittest.main()
