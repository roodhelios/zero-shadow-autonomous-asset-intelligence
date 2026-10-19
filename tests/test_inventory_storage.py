"""Discovery-only persistence must not require fabricated vulnerability claims."""

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from database.inventory_cli import main, store_export
from database.evidence_reader import EvidenceReader, EvidenceReadError
from database.evidence_reader_cli import main as read_main
from database.repository import EvidenceRepository
from engine.correlation import correlate_assets
from engine.models import AssetObservation

FIXTURE = Path(__file__).resolve().parents[1] / "examples/osquery-system-info.json"
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@unittest.skipUnless(os.name == "posix", "private storage requires POSIX")
class InventoryStorageTests(unittest.TestCase):
    def test_store_reopen_and_read_without_inventing_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.sqlite"
            result = store_export(FIXTURE, path, scope="synthetic", observed_at=NOW)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                reader = EvidenceReader(connection)
                snapshot = reader.read_inventory(result["asset_ids"][0]).to_dict()
                self.assertEqual(len(snapshot["observations"]), 1)
                for field in ("findings", "ownership_decisions", "remediation_plans"):
                    self.assertEqual(snapshot[field], [])
                with self.assertRaises(EvidenceReadError):
                    reader.read_asset(result["asset_ids"][0])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(read_main([str(path), "--asset-id", result["asset_ids"][0], "--inventory"]), 0)
            self.assertEqual(json.loads(output.getvalue()), snapshot)
            self.assertEqual(path.read_bytes(), original)
            export = Path(directory) / "snapshot.json"
            with redirect_stdout(StringIO()):
                self.assertEqual(read_main([str(path), "--asset-id", result["asset_ids"][0],
                                            "--inventory", "--output", str(export)]), 0)
            self.assertEqual(export.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(export.read_text()), snapshot)
            with redirect_stderr(StringIO()):
                self.assertEqual(read_main([str(path), "--asset-id", result["asset_ids"][0],
                                            "--inventory", "--output", str(export)]), 2)

    def test_cli_is_exclusive_and_leaves_no_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.sqlite"
            args = [str(FIXTURE), "--output", str(path), "--scope", "synthetic",
                    "--observed-at", "2026-10-19T00:00:00Z"]
            with redirect_stdout(StringIO()):
                self.assertEqual(main(args), 0)
            original = path.read_bytes()
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_bad_timestamp_and_export_do_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.sqlite"
            with redirect_stderr(StringIO()):
                self.assertEqual(main([str(FIXTURE), "--output", str(path), "--scope", "synthetic",
                                       "--observed-at", "2026-10-19"]), 2)
            self.assertEqual(list(Path(directory).iterdir()), [])
            bad_export = Path(directory) / "invalid.json"
            bad_export.write_text('[{"hostname":"not-an-osquery-export"}]')
            with redirect_stderr(StringIO()):
                self.assertEqual(main([str(bad_export), "--output", str(path), "--scope", "synthetic",
                                       "--observed-at", "2026-10-19T00:00:00Z"]), 2)
            self.assertFalse(path.exists())

    def test_batch_collision_rolls_back_all_assets(self):
        with sqlite3.connect(":memory:") as connection:
            connection.executescript(FIXTURE.parents[1].joinpath("database/schema.sql").read_text())
            asset = correlate_assets([AssetObservation.from_dict("fixture", {
                "source_record_id": "one", "kind": "host", "hostname": "one.example.test",
                "tags": {}, "ip_addresses": []})])[0]
            with self.assertRaises(sqlite3.IntegrityError):
                EvidenceRepository(connection).store_inventory((asset, asset), scope="synthetic", observed_at=NOW)
            self.assertEqual(connection.execute("SELECT count(*) FROM assets").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM asset_observations").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
