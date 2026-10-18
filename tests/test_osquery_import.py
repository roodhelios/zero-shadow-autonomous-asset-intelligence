import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from database.evidence_reader import EvidenceReader
from engine.discovery.fixture_discovery import load_fixture
from engine.discovery.osquery_collector import convert_system_info, main
from engine.workflow_runs import run_workflow_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/osquery-system-info.json"


class OsqueryImportTests(unittest.TestCase):
    def test_converter_is_deterministic_and_preserves_input_digest(self):
        data = EXAMPLE.read_bytes()
        result = convert_system_info(data, scope="synthetic")
        self.assertEqual(result, convert_system_info(data, scope="synthetic"))
        self.assertEqual(result["import_metadata"]["input_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["assets"][0]["tags"], {})
        self.assertEqual(result["assets"][0]["hostname"], "checkout.example.test")

    def test_output_loads_as_fixture_and_runs_through_sqlite_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "imported.json"
            self.assertEqual(main([str(EXAMPLE), "--scope", "synthetic", "--output", str(fixture)]), 0)
            batch = load_fixture(fixture)
            self.assertEqual(batch.source, "osquery-system-info")
            self.assertEqual(len(batch.observations), 1)
            if os.name == "posix":
                self.assertEqual(fixture.stat().st_mode & 0o777, 0o600)
            for source, target in (("examples/ownership-directory.json", "ownership-directory.json"),
                                   ("database/schema.sql", "schema.sql")):
                shutil.copyfile(ROOT / source, root / target)
            spec = json.loads((ROOT / "examples/workflow-spec.json").read_text())
            spec["asset_fixture"] = fixture.name
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec))
            result = run_workflow_once(run_id="import-demo", spec_path=spec_path,
                                       schema_path=root / "schema.sql", output_root=root / "runs", allowed_root=root)
            self.assertEqual(len(result.report["checkpoints"]), 6)
            database = root / "runs" / result.run_key / "evidence.sqlite"
            with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as connection:
                snapshot = EvidenceReader(connection).read_asset(result.report["asset_id"]).to_dict()
            self.assertEqual(snapshot["observations"][0]["source"], "osquery-system-info")
            self.assertEqual(snapshot["ownership_decisions"][0]["status"], "unmatched")
            self.assertIsNone(snapshot["ownership_decisions"][0]["team_id"])

    def test_normalizes_hostname_and_uuid_without_guessing_other_fields(self):
        rows = [{"hostname": "CHECKOUT.EXAMPLE.TEST.", "uuid": "11111111222243338444555555555555"}]
        result = convert_system_info(json.dumps(rows).encode(), scope="owned")
        asset = result["assets"][0]
        self.assertEqual(asset["hostname"], "checkout.example.test")
        self.assertEqual(asset["source_record_id"], "11111111-2222-4333-8444-555555555555")
        self.assertEqual(asset["ip_addresses"], [])
        self.assertNotIn("findings", result)

    def test_invalid_rows_are_rejected_as_a_whole(self):
        valid = json.loads(EXAMPLE.read_text())[0]
        cases = [[], {}, [valid, valid], [dict(valid, uuid="")], [dict(valid, uuid="0" * 32)],
                 [dict(valid, hostname="bad\nname")], [dict(valid, hardware_serial="private")],
                 [dict(valid, uuid=123)], [dict(valid, hostname="-bad.test")]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                convert_system_info(json.dumps(rows).encode(), scope="synthetic")
        with self.assertRaises(ValueError):
            convert_system_info(EXAMPLE.read_bytes(), scope="unapproved")

    def test_duplicate_json_fields_and_size_or_row_limits_fail(self):
        with self.assertRaises(ValueError):
            convert_system_info(b'[{"hostname":"a","hostname":"b","uuid":"x"}]', scope="synthetic")
        with patch("engine.discovery.osquery_collector.MAX_INPUT_BYTES", 1):
            with self.assertRaises(ValueError):
                convert_system_info(EXAMPLE.read_bytes(), scope="synthetic")
        with patch("engine.discovery.osquery_collector.MAX_ROWS", 0):
            with self.assertRaises(ValueError):
                convert_system_info(EXAMPLE.read_bytes(), scope="synthetic")

    def test_cli_refuses_existing_output_and_preserves_input(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "assets.json"
            output.write_text("keep")
            original = EXAMPLE.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(EXAMPLE), "--scope", "authorized", "--output", str(output)]), 2)
            self.assertEqual(output.read_text(), "keep")
            self.assertEqual(EXAMPLE.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_invalid_input_produces_no_success_output_or_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "invalid.json"
            target = Path(directory) / "assets.json"
            source.write_text("{}")
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), "--scope", "synthetic", "--output", str(target)]), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertFalse(target.exists())

    def test_failed_publication_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "assets.json"
            with patch("engine.discovery.osquery_collector.os.link", side_effect=OSError("no links")):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(EXAMPLE), "--scope", "synthetic", "--output", str(target)]), 2)
            self.assertEqual(list(Path(directory).iterdir()), [])
