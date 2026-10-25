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

from database.ec2_inventory import store_ec2
from database.inventory_cli import store_export
from engine.discovery_queue_cli import main, plan_discovery
from engine.inventory_queue_cli import plan_inventory
from engine.work_queue_cli import build_from_jsonl

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/"examples/ec2-describe-instances.json"
FINDINGS = ROOT/"examples/ec2-findings.jsonl"
DIRECTORY = ROOT/"examples/ownership-directory.json"
AS_OF = date(2026, 10, 25)


@unittest.skipUnless(os.name == "posix", "private discovery requires POSIX")
class DiscoveryQueueTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.database = self.root/"ec2.sqlite"
        store_ec2(EXPORT, self.database, scope="synthetic", account="111122223333",
            region="us-east-1", observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.rows = FINDINGS.read_bytes()

    def plan(self, rows=None, **options):
        return plan_discovery(self.database, self.rows if rows is None else rows, DIRECTORY.read_bytes(),
            source="ec2", export_data=EXPORT.read_bytes(), as_of=AS_OF, **options)

    def test_reproduced_ec2_uses_existing_priority_rules_and_preserves_inputs(self):
        before = self.database.read_bytes()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.plan()
        self.assertEqual(result["source_kind"], "ec2")
        self.assertEqual(result["queues"], build_from_jsonl(FINDINGS, directory_path=DIRECTORY, as_of=AS_OF))
        self.assertEqual(result["inventory_binding"]["assets_with_supplied_findings"], 1)
        self.assertEqual(result["queues"]["assigned_item_count"], 1)
        self.assertTrue(result["inventory_binding"]["original_export_checked"])
        self.assertEqual(before, self.database.read_bytes())

    def test_osquery_dispatch_matches_existing_planner_and_requires_correct_source(self):
        source = ROOT/"examples/osquery-system-info-expanded.json"; database = self.root/"osquery.sqlite"
        store_export(source, database, scope="synthetic", observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        rows = (ROOT/"examples/inventory-findings.jsonl").read_bytes()
        expected = plan_inventory(database, rows, DIRECTORY.read_bytes(), as_of=AS_OF, export_data=source.read_bytes())
        result = plan_discovery(database, rows, DIRECTORY.read_bytes(), source="osquery",
                                as_of=AS_OF, export_data=source.read_bytes())
        self.assertEqual(result["queues"], expected["queues"])
        self.assertEqual(result["inventory_binding"], expected["inventory_binding"])
        for selected, db, data in (("ec2", database, source.read_bytes()),
                                   ("osquery", self.database, EXPORT.read_bytes()),
                                   ("unknown", database, source.read_bytes())):
            with self.assertRaises((ValueError, sqlite3.DatabaseError)):
                plan_discovery(db, rows, DIRECTORY.read_bytes(), source=selected, as_of=AS_OF, export_data=data)

    def test_empty_findings_and_reviewed_tags_never_infer_facts_from_ec2(self):
        result = self.plan(b"\n")
        self.assertEqual(result["inventory_binding"]["assets_without_supplied_findings"], 1)
        self.assertEqual(result["queues"]["assigned_item_count"], 0)
        row = json.loads(self.rows); row["asset_tags"] = {}
        result = self.plan(json.dumps(row).encode())
        self.assertEqual(result["queues"]["unassigned_item_count"], 1)
        self.assertEqual(result["queues"]["assigned_item_count"], 0)

    def test_unknown_asset_duplicates_and_malformed_or_oversized_findings_reject(self):
        row = json.loads(self.rows); row["finding"]["asset_id"] = "asset-other"
        for rows in (json.dumps(row).encode(), self.rows+self.rows, self.rows+b'not-json',
                     b'{"finding":{},"finding":{}}', b'{"unknown":true}'):
            with self.assertRaises(ValueError): self.plan(rows)
        for name in ("MAX_BYTES", "MAX_LINE_BYTES", "MAX_RECORDS"):
            with patch("engine.discovery_queue_cli."+name, 0), self.assertRaises(ValueError): self.plan()

    def test_multiple_findings_do_not_inflate_asset_coverage(self):
        row = json.loads(self.rows); row["finding"]["finding_id"] = "second-review"
        result = self.plan(self.rows+json.dumps(row).encode()+b"\n")
        self.assertEqual(result["queues"]["assigned_item_count"], 2)
        self.assertEqual(result["inventory_binding"]["assets_with_supplied_findings"], 1)

    def test_changed_source_and_changed_retained_evidence_reject(self):
        with self.assertRaises(ValueError):
            plan_discovery(self.database, self.rows, DIRECTORY.read_bytes(), source="ec2",
                           as_of=AS_OF, export_data=EXPORT.read_bytes()+b"\n")
        with self.assertRaises(ValueError):
            plan_discovery(self.database, self.rows, DIRECTORY.read_bytes(), source="ec2",
                           as_of=AS_OF, export_data=None)
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TRIGGER asset_observations_no_update")
            connection.execute("UPDATE asset_observations SET payload_json='{}'")
        with self.assertRaises(ValueError): self.plan()

    def test_cli_private_output_aggregate_stdout_no_overwrite_or_partial_success(self):
        output = self.root/"queue.json"
        args = [str(self.database), str(FINDINGS), "--source", "ec2", "--export", str(EXPORT),
                "--directory", str(DIRECTORY), "--as-of", AS_OF.isoformat(), "--output", str(output)]
        stdout = StringIO()
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "queues_created")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        for private in ("111122223333", "cloud-platform", "192.0.2.40", "asset-da2fa8d38b931447"):
            self.assertNotIn(private, stdout.getvalue())
        before = output.read_bytes(); stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
        self.assertEqual(before, output.read_bytes()); self.assertEqual(stdout.getvalue(), "")
        output.unlink(); bad = self.root/"bad.jsonl"; bad.write_bytes(self.rows+b"private-marker")
        args[1] = str(bad); stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr): self.assertEqual(main(args), 2)
        self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("private-marker", stderr.getvalue())
