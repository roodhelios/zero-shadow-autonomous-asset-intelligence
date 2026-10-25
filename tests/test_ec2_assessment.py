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
from unittest.mock import patch

from database.ec2_assessment import current_model, export_review, main, retain_assessment, verify_assessment
from database.ec2_inventory import store_ec2, verify_ec2
from database.inventory_assessment_verify import _snapshot

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/"examples/ec2-describe-instances.json"
FINDINGS = ROOT/"examples/ec2-findings.jsonl"
DIRECTORY = ROOT/"examples/ownership-directory.json"
TIME = datetime(2026, 10, 25, 1, tzinfo=timezone.utc)


@unittest.skipUnless(os.name == "posix", "private receipts require POSIX")
class EC2AssessmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.discovery = self.root/"discovery.sqlite"
        self.receipt = self.root/"assessment.sqlite"
        store_ec2(EXPORT, self.discovery, scope="synthetic", account="111122223333",
                  region="us-east-1", observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def retain(self, **options):
        return retain_assessment(self.discovery, FINDINGS.read_bytes(), DIRECTORY.read_bytes(),
            self.receipt, export_data=EXPORT.read_bytes(), as_of=date(2026, 10, 25),
            assessed_at=TIME, **options)

    def verify(self):
        return verify_assessment(self.receipt, EXPORT.read_bytes())

    def mutate(self, change):
        with sqlite3.connect(self.receipt) as connection:
            connection.execute("DROP TRIGGER assessment_no_update")
            record = json.loads(connection.execute("SELECT payload_json FROM ec2_assessment_record").fetchone()[0])
            change(record)
            payload = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            connection.execute("UPDATE ec2_assessment_record SET payload_json=?,payload_sha256=?",
                               (payload, hashlib.sha256(payload.encode()).hexdigest()))

    def test_receipt_reproduces_without_discovery_database_or_separate_review_inputs(self):
        original = self.discovery.read_bytes()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            stored = self.retain()
            self.assertEqual(original, self.discovery.read_bytes())
            self.assertEqual(verify_ec2(self.discovery, EXPORT.read_bytes())["asset_count"], 1)
            self.discovery.unlink(); result = self.verify()
        self.assertEqual(stored["status"], "ec2_assessment_stored")
        self.assertEqual(result["status"], "ec2_assessment_reproduced")
        self.assertEqual((result["asset_count"], result["assessed_asset_count"], result["finding_count"]), (1, 1, 1))
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        for private in ("111122223333", "cloud-platform", "192.0.2.40", "asset-da2fa8d38b931447"):
            self.assertNotIn(private, json.dumps(result))

    def test_private_review_reproduces_before_exporting_and_never_overwrites(self):
        self.retain(); before = self.receipt.read_bytes(); output = self.root/"review.json"
        result = export_review(self.receipt, EXPORT.read_bytes(), output)
        report = json.loads(output.read_bytes())
        self.assertEqual(result["status"], "ec2_assessment_exported")
        self.assertEqual(report["report_type"], "retained-ec2-assessment-review")
        self.assertEqual(report["queue_report"]["queues"]["queues"][0]["team_id"], "cloud-platform")
        self.assertNotIn("findings_jsonl", report)
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        saved = output.read_bytes()
        with self.assertRaises(FileExistsError): export_review(self.receipt, EXPORT.read_bytes(), output)
        self.assertEqual(saved, output.read_bytes())

    def test_review_uses_the_same_verified_snapshot_if_original_receipt_disappears(self):
        self.retain(); output = self.root/"review.json"
        def snapshot_then_remove(source, destination):
            _snapshot(source, destination); source.unlink()
        with patch("database.ec2_assessment._snapshot", side_effect=snapshot_then_remove) as copied:
            self.assertEqual(export_review(self.receipt, EXPORT.read_bytes(), output)["finding_count"], 1)
        self.assertEqual(copied.call_count, 1)

    def test_changed_export_and_changed_model_are_rejected(self):
        self.retain()
        with self.assertRaises(ValueError): verify_assessment(self.receipt, EXPORT.read_bytes()+b"\n")
        changed = current_model(); changed["model_version"] = 2
        with patch("database.ec2_assessment.current_model", return_value=changed), self.assertRaises(ValueError):
            self.verify()

    def test_append_only_receipt_and_recomputed_queue_tampering_reject(self):
        self.retain()
        with sqlite3.connect(self.receipt) as connection:
            with self.assertRaises(sqlite3.IntegrityError): connection.execute("DELETE FROM ec2_assessment_record")
            with self.assertRaises(sqlite3.IntegrityError): connection.execute("UPDATE ec2_assessment_record SET singleton=1")
        self.mutate(lambda record: record["queue_report"]["queues"]["queues"][0]["items"][0].update(priority="P0"))
        output = self.root/"failed.json"
        with self.assertRaises(ValueError): export_review(self.receipt, EXPORT.read_bytes(), output)
        self.assertFalse(output.exists())

    def test_changed_discovery_and_retained_input_are_recomputed(self):
        self.retain()
        self.mutate(lambda record: record["discovery"]["import_context"].update(region="us-west-2"))
        with self.assertRaises(ValueError): self.verify()
        self.receipt.unlink(); self.retain()
        self.mutate(lambda record: record.update(findings_jsonl=record["findings_jsonl"]+"\n"))
        with self.assertRaises(ValueError): self.verify()

    def test_consistent_assessment_time_remains_a_caller_claim(self):
        self.retain()
        self.mutate(lambda record: record.update(assessed_at="2026-10-25T02:00:00Z"))
        self.assertEqual(self.verify()["finding_count"], 1)
        output = self.root/"review.json"
        export_review(self.receipt, EXPORT.read_bytes(), output)
        self.assertEqual(json.loads(output.read_bytes())["assessed_at"], "2026-10-25T02:00:00Z")

    def test_invalid_temporal_empty_and_partial_work_never_publish(self):
        with self.assertRaises(ValueError):
            retain_assessment(self.discovery, b"", DIRECTORY.read_bytes(), self.receipt,
                export_data=EXPORT.read_bytes(), as_of=date(2026, 10, 25), assessed_at=TIME)
        for as_of, assessed_at in ((date(2026, 10, 23), TIME),
                                   (date(2026, 10, 25), datetime(2026, 10, 23, tzinfo=timezone.utc))):
            with self.assertRaises(ValueError):
                retain_assessment(self.discovery, FINDINGS.read_bytes(), DIRECTORY.read_bytes(), self.receipt,
                    export_data=EXPORT.read_bytes(), as_of=as_of, assessed_at=assessed_at)
        with patch("database.ec2_assessment.verify_assessment", side_effect=ValueError("fixture failure")):
            with self.assertRaises(ValueError): self.retain()
        self.assertFalse(self.receipt.exists()); self.assertEqual(list(self.root.glob('.ec2-assessment-*')), [])

    def test_unsupported_tables_views_sidecars_and_symlinks_are_rejected(self):
        self.retain(); link = self.root/"link"; link.symlink_to(self.receipt)
        with self.assertRaises(OSError): verify_assessment(link, EXPORT.read_bytes())
        sidecar = Path(str(self.receipt)+"-wal"); sidecar.touch()
        with self.assertRaises(ValueError): self.verify()
        sidecar.unlink()
        with sqlite3.connect(self.receipt) as connection: connection.execute("CREATE VIEW extra AS SELECT 1")
        with self.assertRaises(ValueError): self.verify()
        with sqlite3.connect(self.receipt) as connection:
            connection.execute("DROP VIEW extra"); connection.execute("CREATE TABLE extra(value TEXT)")
        with self.assertRaises(ValueError): self.verify()

    def test_size_bound_and_cli_no_overwrite_or_private_failure_output(self):
        with patch("database.ec2_assessment.MAX_RECEIPT_BYTES", 1), self.assertRaises(ValueError): self.retain()
        self.assertFalse(self.receipt.exists())
        args = ["retain", str(self.discovery), str(FINDINGS), "--directory", str(DIRECTORY),
                "--as-of", "2026-10-25", "--assessed-at", "2026-10-25T01:00:00Z",
                "--export", str(EXPORT), "--output", str(self.receipt)]
        stdout = StringIO()
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ec2_assessment_stored")
        original = self.receipt.read_bytes(); stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
        self.assertEqual(stdout.getvalue(), ""); self.assertEqual(original, self.receipt.read_bytes())
        bad = self.root/"bad.json"; bad.write_text("private-fixture-marker")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(["verify", str(self.receipt), "--export", str(bad)]), 2)
        self.assertEqual(stdout.getvalue(), ""); self.assertNotIn("private-fixture-marker", stderr.getvalue())
