"""Review readback checks aggregate coverage, not reviewer identity or batch identity."""

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_cli import store_export
from database.inventory_export_cli import export_inventory, review_record
from database.inventory_review_verify import main, verify_review

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples/osquery-system-info-expanded.json"


@unittest.skipUnless(os.name == "posix", "inventory fixtures require POSIX")
class ReviewVerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / "inventory.sqlite"
        store_export(FIXTURE, self.database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.record = review_record(export_inventory(self.database, export_data=FIXTURE.read_bytes()),
                                    reviewed_at="2026-10-23T05:00:00Z",
                                    reviewer_note="Synthetic coverage handoff.")

    def verify(self, record, *, export_data=FIXTURE.read_bytes()):
        return verify_review(self.database, json.dumps(record).encode(), export_data=export_data)

    def test_record_reproduces_without_copying_identifiers_or_notes(self):
        before = self.database.read_bytes()
        result = self.verify(self.record)
        self.assertEqual(result["status"], "consistent")
        self.assertEqual(result["review_sha256"], self.record["review_sha256"])
        self.assertEqual(result["asset_count"], 2)
        self.assertTrue(result["original_export_checked"])
        for private in ("checkout.example.test", "Synthetic coverage handoff."):
            self.assertNotIn(private, json.dumps(result))
        self.assertEqual(before, self.database.read_bytes())

    def test_changed_digest_note_or_unknown_field_fails(self):
        changes = {"review_sha256": "0" * 64, "reviewer_note": "Different note.",
                   "unexpected": "private-fixture-marker", "schema_version": True}
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = dict(self.record, **{field: value})
                with self.assertRaises(ValueError):
                    self.verify(changed)

    def test_rehashed_wrong_coverage_still_fails_against_database(self):
        wrong_inventory = export_inventory(self.database, export_data=FIXTURE.read_bytes())
        wrong_inventory["assets"][0]["findings"] = [{"finding_id": "synthetic"}]
        wrong = review_record(wrong_inventory, reviewed_at=self.record["reviewed_at"],
                              reviewer_note=self.record["reviewer_note"])
        with self.assertRaises(ValueError):
            self.verify(wrong)

    def test_checked_and_unchecked_source_modes_must_match(self):
        with self.assertRaises(ValueError):
            self.verify(self.record, export_data=None)
        unchecked = review_record(export_inventory(self.database),
                                  reviewed_at=self.record["reviewed_at"],
                                  reviewer_note=self.record["reviewer_note"])
        self.assertFalse(self.verify(unchecked, export_data=None)["original_export_checked"])
        with self.assertRaises(ValueError):
            self.verify(self.record, export_data=FIXTURE.read_bytes() + b"\n")

    def test_strict_record_bounds_and_duplicate_fields(self):
        duplicate = json.dumps(self.record)[:-1] + ', "schema_version": 1}'
        for data in (duplicate.encode(), b"[]", b"x" * (16384 + 1), b'{"reviewed_at":null}'):
            with self.subTest(length=len(data)), self.assertRaises((ValueError, TypeError)):
                verify_review(self.database, data)

    def test_equal_coverage_cannot_identify_a_different_batch(self):
        # Metadata-only review records deliberately contain no identity digest.
        different = json.loads(FIXTURE.read_bytes())
        different[0]["hostname"] = "other.example.test"
        source = self.root / "different.json"
        source.write_text(json.dumps(different))
        database = self.root / "different.sqlite"
        store_export(source, database, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        result = verify_review(database, json.dumps(self.record).encode(),
                               export_data=source.read_bytes())
        self.assertEqual(result["status"], "consistent")
        self.assertIn("does not", result["interpretation"])

    def test_cli_success_and_failure_do_not_echo_review_text(self):
        path = self.root / "review.json"
        path.write_text(json.dumps(self.record))
        output = StringIO()
        arguments = [str(self.database), str(path), "--export", str(FIXTURE)]
        with redirect_stdout(output):
            self.assertEqual(main(arguments), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "consistent")
        path.write_text('{"private":"private-fixture-marker"}')
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(arguments), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("private-fixture-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
