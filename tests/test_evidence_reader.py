"""Tests for deterministic read-side evidence reconstruction."""

from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from database.evidence_reader import EvidenceReadError, EvidenceReader
from database.evidence_reader_cli import main
from engine.evidence_workflow import load_workflow_spec, run_fixture_workflow


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "database" / "schema.sql"
SPEC_PATH = ROOT / "examples" / "workflow-spec.json"


class EvidenceReaderTests(unittest.TestCase):
    def populated_connection(self, path: str = ":memory:") -> tuple[sqlite3.Connection, str]:
        connection = sqlite3.connect(path)
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        report = run_fixture_workflow(
            load_workflow_spec(SPEC_PATH, allowed_root=ROOT),
            connection=connection,
        )
        return connection, report.asset_id

    def test_reconstructs_complete_linked_snapshot(self) -> None:
        connection, asset_id = self.populated_connection()
        try:
            snapshot = EvidenceReader(connection).read_asset(asset_id).to_dict()
        finally:
            connection.close()

        self.assertEqual(snapshot["asset"]["asset_id"], asset_id)
        self.assertEqual(len(snapshot["observations"]), 1)
        self.assertEqual(len(snapshot["findings"]), 1)
        self.assertEqual(len(snapshot["ownership_decisions"]), 1)
        self.assertEqual(len(snapshot["remediation_plans"]), 1)
        self.assertEqual(len(snapshot["snapshot_sha256"]), 64)

    def test_snapshot_order_and_digest_are_deterministic(self) -> None:
        connection, asset_id = self.populated_connection()
        try:
            first = EvidenceReader(connection).read_asset(asset_id).to_dict()
            second = EvidenceReader(connection).read_asset(asset_id).to_dict()
        finally:
            connection.close()

        self.assertEqual(first, second)
        observation_ids = [
            item["observation_id"] for item in first["observations"]
        ]
        self.assertEqual(observation_ids, sorted(observation_ids))

    def test_unknown_asset_fails_without_fallback(self) -> None:
        connection, _ = self.populated_connection()
        try:
            with self.assertRaisesRegex(EvidenceReadError, "was not found"):
                EvidenceReader(connection).read_asset("asset-not-present")
        finally:
            connection.close()

    def test_payload_column_mismatch_is_detected(self) -> None:
        connection, asset_id = self.populated_connection()
        try:
            connection.execute("DROP TRIGGER asset_observations_no_update")
            row = connection.execute(
                "SELECT observation_id, payload_json FROM asset_observations LIMIT 1"
            ).fetchone()
            payload = json.loads(row[1])
            payload["source"] = "changed-source"
            connection.execute(
                "UPDATE asset_observations SET payload_json = ? WHERE observation_id = ?",
                (json.dumps(payload), row[0]),
            )
            with self.assertRaisesRegex(EvidenceReadError, "does not match"):
                EvidenceReader(connection).read_asset(asset_id)
        finally:
            connection.close()

    def test_missing_linked_evidence_is_rejected(self) -> None:
        connection, asset_id = self.populated_connection()
        try:
            connection.execute("DROP TRIGGER ownership_decisions_no_delete")
            connection.execute("DELETE FROM ownership_decisions")
            with self.assertRaisesRegex(EvidenceReadError, "no retained ownership"):
                EvidenceReader(connection).read_asset(asset_id)
        finally:
            connection.close()

    def test_cli_reads_database_in_place_and_writes_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "evidence.sqlite"
            output = root / "snapshot.json"
            connection, asset_id = self.populated_connection(str(database))
            connection.close()

            status = main(
                [
                    str(database),
                    "--asset-id",
                    asset_id,
                    "--output",
                    str(output),
                ]
            )
            snapshot = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(snapshot["asset"]["asset_id"], asset_id)

    def test_cli_refuses_existing_output_and_reports_error(self) -> None:
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "evidence.sqlite"
            output = root / "snapshot.json"
            connection, asset_id = self.populated_connection(str(database))
            connection.close()
            output.write_text("keep", encoding="utf-8")

            with redirect_stderr(errors):
                status = main(
                    [
                        str(database),
                        "--asset-id",
                        asset_id,
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(status, 2)
        self.assertIn("output already exists", errors.getvalue())

    def test_cli_can_render_to_stdout(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "evidence.sqlite"
            connection, asset_id = self.populated_connection(str(database))
            connection.close()
            with redirect_stdout(output):
                status = main([str(database), "--asset-id", asset_id])

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
