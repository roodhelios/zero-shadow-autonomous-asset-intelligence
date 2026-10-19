"""An import receipt must survive reopening and reconcile with source claims."""

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
from database.inventory_receipt import read_receipt, main

FIXTURE = Path(__file__).resolve().parents[1] / "examples/osquery-system-info.json"


@unittest.skipUnless(os.name == "posix", "inventory publication requires POSIX")
class InventoryReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "inventory.sqlite"
        self.result = store_export(FIXTURE, self.path, scope="synthetic",
                                  observed_at=datetime(2026, 10, 19, tzinfo=timezone.utc))

    def test_receipt_survives_reopen_and_reproduces_original_export(self):
        before = self.path.read_bytes()
        with sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True) as connection:
            receipt = read_receipt(connection, export_data=FIXTURE.read_bytes())
            self.assertEqual(receipt["receipt_sha256"], self.result["receipt_sha256"])
            self.assertEqual(receipt["receipt"]["observed_at"], "2026-10-19T00:00:00Z")
            self.assertTrue(receipt["original_export_checked"])
        self.assertEqual(before, self.path.read_bytes())

    def test_original_byte_changes_are_detected_even_if_inventory_matches(self):
        with sqlite3.connect(self.path) as connection:
            with self.assertRaisesRegex(ValueError, "export"):
                read_receipt(connection, export_data=FIXTURE.read_bytes() + b"\n")

    def test_receipt_is_append_only(self):
        with sqlite3.connect(self.path) as connection:
            for sql in ("DELETE FROM inventory_import_receipt", "UPDATE inventory_import_receipt SET receipt_sha256='x'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(sql)

    def test_receipt_corruption_and_metadata_mismatch_fail(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TRIGGER inventory_receipt_no_update")
            payload, digest = connection.execute("SELECT payload_json, receipt_sha256 FROM inventory_import_receipt").fetchone()
            for value in ("{}", payload.replace('"synthetic"', '"authorized"')):
                connection.execute("UPDATE inventory_import_receipt SET payload_json=?", (value,))
                with self.assertRaises(ValueError):
                    read_receipt(connection)
            connection.execute("UPDATE inventory_import_receipt SET payload_json=?, receipt_sha256='bad'", (payload,))
            with self.assertRaises(ValueError):
                read_receipt(connection)
            connection.execute("UPDATE inventory_import_receipt SET receipt_sha256=?", (digest,))
            connection.execute("DROP TRIGGER asset_observations_no_update")
            connection.execute("UPDATE asset_observations SET scope='authorized'")
            with self.assertRaisesRegex(ValueError, "metadata"):
                read_receipt(connection)

    def test_cli_can_read_without_export_and_fails_without_receipt(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(self.path)]), 0)
        self.assertFalse(json.loads(output.getvalue())["original_export_checked"])
        with sqlite3.connect(self.path) as connection:
            connection.execute("DROP TABLE inventory_import_receipt")
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(StringIO()):
            self.assertEqual(main([str(self.path)]), 2)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
