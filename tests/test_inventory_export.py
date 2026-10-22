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
from database.inventory_export_cli import (
    coverage_summary,
    export_inventory,
    main,
    review_record,
    review_summary,
)

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

    def test_text_summary_lists_every_host_without_inventing_assessment(self):
        before = self.path.read_bytes()
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(self.path), "--export", str(FIXTURE), "--format", "text"]), 0)
        text = output.getvalue()
        self.assertIn("Retained inventory: 2 assets, 2 observations", text)
        self.assertIn('Claimed scope: "synthetic"', text)
        self.assertIn('Observed at: "2026-10-20T00:00:00Z"', text)
        self.assertIn("Original export: checked", text)
        for asset_id in self.receipt["asset_ids"]:
            self.assertIn(asset_id, text)
        self.assertIn('"checkout.example.test"', text)
        self.assertIn('"worker.example.test"', text)
        self.assertEqual(text.count("Findings: 0 (not assessed by this import)"), 2)
        self.assertEqual(text.count("Ownership decisions: 0; remediation plans: 0"), 2)
        self.assertNotIn("payload", text)
        self.assertEqual(before, self.path.read_bytes())

    def test_text_output_is_private_exclusive_and_marks_unchecked_source(self):
        output = self.path.with_suffix(".txt")
        self.assertEqual(main([str(self.path), "--format", "text", "--output", str(output)]), 0)
        before = output.read_bytes()
        self.assertIn(b"Original export: not checked", before)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with redirect_stderr(StringIO()):
            self.assertEqual(main([str(self.path), "--format", "text", "--output", str(output)]), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_summary_quotes_terminal_controls_and_does_not_call_retained_findings_safe(self):
        result = export_inventory(self.path)
        result["assets"][0]["asset"]["primary_hostname"] = "host\n\x1b[31m\u202e"
        result["assets"][0]["findings"] = [{"private": "not-rendered"}]
        text = review_summary(result)
        self.assertIn('hostname "host\\n\\u001b[31m\\u202e"', text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("Findings: 1 (retained records)", text)
        self.assertNotIn("not-rendered", text)

    def test_json_default_is_unchanged_and_explicit_json_matches(self):
        outputs = []
        for extra in ([], ["--format", "json"]):
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(self.path), *extra]), 0)
            outputs.append(output.getvalue())
        expected = json.dumps(export_inventory(self.path), sort_keys=True, indent=2, allow_nan=False) + "\n"
        self.assertEqual(outputs, [expected, expected])

    def test_coverage_summary_reports_only_aggregate_record_presence(self):
        result = export_inventory(self.path, export_data=FIXTURE.read_bytes())
        result["assets"][0]["findings"] = [{"finding_id": "not-published"}]
        result["assets"][0]["ownership_decisions"] = [{"team": "not-published"}]
        result["assets"][1]["remediation_plans"] = [{"plan_id": "not-published"}]

        summary = coverage_summary(result)

        self.assertEqual(summary["report_type"], "inventory-coverage-summary")
        self.assertEqual(summary["asset_count"], 2)
        self.assertEqual(summary["observation_count"], 2)
        self.assertEqual(summary["receipt_status"], "consistent")
        self.assertTrue(summary["original_export_checked"])
        self.assertEqual(summary["record_coverage"], {
            "assets_with_findings": 1,
            "assets_without_findings": 1,
            "assets_with_ownership_decisions": 1,
            "assets_without_ownership_decisions": 1,
            "assets_with_remediation_plans": 1,
            "assets_without_remediation_plans": 1,
        })
        self.assertFalse(summary["identifiers_included"])
        self.assertFalse(summary["evidence_included"])
        rendered = json.dumps(summary)
        for private in ("not-published", "checkout.example.test", *self.receipt["asset_ids"]):
            self.assertNotIn(private, rendered)
        self.assertIn("Missing records do not mean", summary["interpretation"])

    def test_coverage_cli_uses_reconciled_database_without_identifiers(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(self.path), "--export", str(FIXTURE),
                                   "--format", "coverage"]), 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["record_coverage"], {
            "assets_with_findings": 0,
            "assets_without_findings": 2,
            "assets_with_ownership_decisions": 0,
            "assets_without_ownership_decisions": 2,
            "assets_with_remediation_plans": 0,
            "assets_without_remediation_plans": 2,
        })
        self.assertTrue(document["original_export_checked"])
        for private in ("checkout.example.test", "worker.example.test", *self.receipt["asset_ids"]):
            self.assertNotIn(private, output.getvalue())

    def test_review_record_binds_note_and_normalized_time_to_coverage(self):
        result = export_inventory(self.path, export_data=FIXTURE.read_bytes())
        record = review_record(
            result,
            reviewed_at="2026-10-22T01:30:00-04:00",
            reviewer_note="Checked retained record coverage before assessment handoff.",
        )
        self.assertEqual(record["report_type"], "inventory-review-record")
        self.assertEqual(record["reviewed_at"], "2026-10-22T05:30:00Z")
        self.assertEqual(len(record["review_sha256"]), 64)
        self.assertEqual(record["coverage_summary"], coverage_summary(result))
        self.assertFalse(record["coverage_summary"]["identifiers_included"])
        self.assertFalse(record["coverage_summary"]["evidence_included"])
        self.assertIn("does not authenticate", record["interpretation"])
        changed = review_record(
            result,
            reviewed_at="2026-10-22T01:30:00-04:00",
            reviewer_note="A different review note.",
        )
        self.assertNotEqual(record["review_sha256"], changed["review_sha256"])

    def test_review_cli_is_deterministic_and_keeps_identifiers_out(self):
        args = [
            str(self.path),
            "--export", str(FIXTURE),
            "--format", "review",
            "--reviewed-at", "2026-10-22T05:30:00Z",
            "--reviewer-note", "Coverage checked for synthetic handoff.",
        ]
        outputs = []
        for _ in range(2):
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 0)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        document = json.loads(outputs[0])
        self.assertTrue(document["coverage_summary"]["original_export_checked"])
        for private in (
            "checkout.example.test",
            "worker.example.test",
            *self.receipt["asset_ids"],
        ):
            self.assertNotIn(private, outputs[0])

    def test_review_metadata_validation_fails_without_output(self):
        invalid = (
            ["--format", "review"],
            ["--format", "review", "--reviewed-at", "2026-10-22T05:30:00Z",
             "--reviewer-note", "line one\nline two"],
            ["--format", "review", "--reviewed-at", "2026-10-22T05:30:00",
             "--reviewer-note", "Missing timezone."],
            ["--format", "coverage", "--reviewer-note", "Wrong format."],
        )
        for extra in invalid:
            with self.subTest(extra=extra):
                stdout = StringIO()
                with redirect_stdout(stdout), redirect_stderr(StringIO()):
                    self.assertEqual(main([str(self.path), *extra]), 2)
                self.assertEqual(stdout.getvalue(), "")

    def test_failed_reconciliation_emits_no_text_or_output(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE inventory_import_receipt")
        output = self.path.with_suffix(".txt")
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(main([str(self.path), "--format", "text", "--output", str(output)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(output.exists())

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
