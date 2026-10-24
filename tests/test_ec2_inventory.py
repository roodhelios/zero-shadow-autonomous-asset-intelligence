import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import main, store_ec2, verify_ec2

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/"examples/ec2-describe-instances.json"


@unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
class EC2InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.database = self.root/"inventory.sqlite"
        self.stored = store_ec2(EXPORT, self.database, scope="synthetic", account="111122223333",
            region="us-east-1", observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))

    def verify(self):
        return verify_ec2(self.database, EXPORT.read_bytes())

    def test_native_reproduction_keeps_original_bytes_and_omits_raw_observations(self):
        before = self.database.read_bytes()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.verify()
        self.assertEqual(result["status"], "ec2_inventory_reproduced")
        self.assertEqual((result["asset_count"], result["observation_count"]), (1, 1))
        self.assertEqual(result["input_sha256"], hashlib.sha256(EXPORT.read_bytes()).hexdigest())
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        for private in ("192.0.2.40", "111122223333", "cloud-platform", "i-0123456789abcdef0"):
            self.assertNotIn(private, json.dumps(result))

    def test_changed_original_bytes_fail_even_when_json_meaning_is_unchanged(self):
        with self.assertRaises(ValueError):
            verify_ec2(self.database, EXPORT.read_bytes()+b"\n")

    def test_context_is_append_only_and_recomputed_tampering_still_fails(self):
        with sqlite3.connect(self.database) as connection:
            with self.assertRaises(sqlite3.IntegrityError): connection.execute("DELETE FROM ec2_import_context")
            connection.execute("DROP TRIGGER ec2_context_no_update")
            context = json.loads(connection.execute("SELECT context_json FROM ec2_import_context").fetchone()[0])
            context["source_records"][0]["instance_record"] = 2
            payload = json.dumps(context, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            connection.execute("UPDATE ec2_import_context SET context_json=?,context_sha256=?",
                               (payload, hashlib.sha256(payload.encode()).hexdigest()))
        with self.assertRaises(ValueError): self.verify()

    def test_changed_retained_payload_does_not_reproduce(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TRIGGER asset_observations_no_update")
            payload = json.loads(connection.execute("SELECT payload_json FROM asset_observations").fetchone()[0])
            payload["ip_addresses"] = ["192.0.2.99"]
            connection.execute("UPDATE asset_observations SET payload_json=?", (json.dumps(payload),))
        with self.assertRaises(ValueError): self.verify()

    def test_views_and_uncheckpointed_or_symlinked_database_are_rejected(self):
        link = self.root/"link.sqlite"; link.symlink_to(self.database)
        with self.assertRaises((OSError, ValueError)): verify_ec2(link, EXPORT.read_bytes())
        journal = Path(str(self.database)+"-wal"); journal.touch()
        with self.assertRaises(ValueError): self.verify()
        journal.unlink()
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE VIEW unexpected AS SELECT 1")
        with self.assertRaises(ValueError): self.verify()
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP VIEW unexpected")
            connection.execute("CREATE TABLE unexpected(value TEXT)")
        with self.assertRaises(ValueError): self.verify()

    def test_no_output_when_prepublication_verification_fails_or_input_is_empty(self):
        new = self.root/"new.sqlite"
        with patch("database.ec2_inventory.verify_ec2", side_effect=ValueError("synthetic failure")):
            with self.assertRaises(ValueError):
                store_ec2(EXPORT, new, scope="synthetic", account="111122223333", region="us-east-1",
                          observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.assertFalse(new.exists()); self.assertEqual(list(self.root.glob('.ec2-inventory-*')), [])
        empty = self.root/"empty.json"; empty.write_text('{"Reservations":[]}')
        with self.assertRaises(ValueError):
            store_ec2(empty, new, scope="synthetic", account="111122223333", region="us-east-1",
                      observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.assertFalse(new.exists())

    def test_cli_never_overwrites_and_failed_verification_emits_no_success(self):
        args = ["store", str(EXPORT), "--output", str(self.database), "--scope", "synthetic",
                "--account", "111122223333", "--region", "us-east-1", "--observed-at", "2026-10-24T00:00:00Z"]
        before = self.database.read_bytes(); stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
        self.assertEqual(stdout.getvalue(), ""); self.assertEqual(self.database.read_bytes(), before)
        bad = self.root/"changed.json"; bad.write_bytes(EXPORT.read_bytes()+b"\n")
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(main(["verify", str(self.database), "--export", str(bad)]), 2)
        self.assertEqual(stdout.getvalue(), "")
