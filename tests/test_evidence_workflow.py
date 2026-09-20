"""Tests for the fixture-only evidence workflow and Airflow boundary."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from engine.evidence_workflow import (
    EvidenceWorkflowError,
    load_workflow_spec,
    run_fixture_workflow,
    run_workflow_to_sqlite,
)


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "examples" / "workflow-spec.json"
SCHEMA_PATH = ROOT / "database" / "schema.sql"
DAG_PATH = ROOT / "airflow" / "dags" / "asset_discovery_dag.py"


class EvidenceWorkflowTests(unittest.TestCase):
    def connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        return connection

    def test_repository_fixture_reaches_all_checkpoints(self) -> None:
        connection = self.connection()
        try:
            report = run_fixture_workflow(
                load_workflow_spec(SPEC_PATH, allowed_root=ROOT),
                connection=connection,
            )
            tables = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "assets",
                    "asset_observations",
                    "findings",
                    "ownership_decisions",
                    "remediation_plans",
                )
            }
        finally:
            connection.close()

        self.assertEqual(
            [item.checkpoint for item in report.checkpoints],
            [
                "fixture_loaded",
                "asset_correlated",
                "risk_scored",
                "ownership_resolved",
                "remediation_planned",
                "evidence_persisted",
            ],
        )
        self.assertEqual(tables, {name: 1 for name in tables})

    def test_output_files_are_new_and_reviewable(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory)
            database = output / "evidence.sqlite"
            report_path = output / "report.json"
            result = run_workflow_to_sqlite(
                spec_path=SPEC_PATH,
                schema_path=SCHEMA_PATH,
                database_path=database,
                report_path=report_path,
                allowed_root=ROOT,
            )
            saved = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(saved, result.to_dict())
        self.assertEqual(saved["status"], "completed")
        self.assertEqual(len(saved["checkpoints"]), 6)

    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory)
            database = output / "evidence.sqlite"
            report_path = output / "report.json"
            report_path.write_text("keep-me", encoding="utf-8")

            with self.assertRaisesRegex(EvidenceWorkflowError, "already exists"):
                run_workflow_to_sqlite(
                    spec_path=SPEC_PATH,
                    schema_path=SCHEMA_PATH,
                    database_path=database,
                    report_path=report_path,
                    allowed_root=ROOT,
                )

            self.assertEqual(report_path.read_text(encoding="utf-8"), "keep-me")

    def test_remote_and_parent_paths_are_rejected(self) -> None:
        value = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source = Path(directory) / "spec.json"
            for candidate in ("https://example.test/assets.json", "../../outside.json"):
                with self.subTest(candidate=candidate):
                    value["asset_fixture"] = candidate
                    source.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(EvidenceWorkflowError):
                        load_workflow_spec(source, allowed_root=ROOT)

    def test_conflicting_tags_fail_before_storage(self) -> None:
        spec = load_workflow_spec(SPEC_PATH, allowed_root=ROOT)
        fixture = json.loads(spec.asset_fixture.read_text(encoding="utf-8"))
        fixture["assets"].append(
            {
                **fixture["assets"][0],
                "source_record_id": "server-checkout-2",
                "tags": {"service": "payments"},
            }
        )
        with tempfile.TemporaryDirectory(dir=ROOT / "examples") as directory:
            fixture_path = Path(directory) / "assets.json"
            fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
            changed = replace(spec, asset_fixture=fixture_path)
            connection = self.connection()
            try:
                with self.assertRaisesRegex(EvidenceWorkflowError, "conflicting tag"):
                    run_fixture_workflow(changed, connection=connection)
                count = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            finally:
                connection.close()

        self.assertEqual(count, 0)

    def test_airflow_module_imports_without_airflow_dependency(self) -> None:
        module_spec = importlib.util.spec_from_file_location("fixture_dag", DAG_PATH)
        self.assertIsNotNone(module_spec)
        self.assertIsNotNone(module_spec.loader)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)

        self.assertIsNone(module.dag)
        self.assertEqual(module.preflight()["scope_boundary"], "local-files-only")


if __name__ == "__main__":
    unittest.main()
