"""Tests for run-scoped fixture outputs and safe retry behavior."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from engine.evidence_workflow import EvidenceWorkflowError
from engine.workflow_runs import run_workflow_once


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "examples" / "workflow-spec.json"
SCHEMA_PATH = ROOT / "database" / "schema.sql"
DAG_PATH = ROOT / "airflow" / "dags" / "asset_discovery_dag.py"


class WorkflowRunTests(unittest.TestCase):
    def execute(self, output_root: Path, run_id: str = "manual__fixture"):
        return run_workflow_once(
            run_id=run_id,
            spec_path=SPEC_PATH,
            schema_path=SCHEMA_PATH,
            output_root=output_root,
            allowed_root=ROOT,
        )

    def fixture_copy(self, directory: Path) -> tuple[Path, Path]:
        for name in (
            "workflow-spec.json",
            "workflow-assets.json",
            "ownership-directory.json",
        ):
            shutil.copyfile(ROOT / "examples" / name, directory / name)
        shutil.copyfile(SCHEMA_PATH, directory / "schema.sql")
        return directory / "workflow-spec.json", directory / "schema.sql"

    def test_retry_reuses_verified_completed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            outputs = Path(directory) / "runs"

            first = self.execute(outputs)
            second = self.execute(outputs)
            run_directory = outputs / first.run_key
            with sqlite3.connect(run_directory / "evidence.sqlite") as connection:
                asset_count = connection.execute(
                    "SELECT COUNT(*) FROM assets"
                ).fetchone()[0]

        self.assertFalse(first.reused)
        self.assertTrue(second.reused)
        self.assertEqual(first.report, second.report)
        self.assertEqual(asset_count, 1)

    def test_changed_input_is_rejected_for_same_run_id(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            workspace = Path(directory)
            spec, schema = self.fixture_copy(workspace)
            outputs = workspace / "runs"
            run_workflow_once(
                run_id="manual__changed-input",
                spec_path=spec,
                schema_path=schema,
                output_root=outputs,
                allowed_root=ROOT,
            )
            assets = workspace / "workflow-assets.json"
            value = json.loads(assets.read_text(encoding="utf-8"))
            value["assets"][0]["tags"]["review"] = "changed"
            assets.write_text(json.dumps(value), encoding="utf-8")

            with self.assertRaisesRegex(
                EvidenceWorkflowError,
                "input evidence changed",
            ):
                run_workflow_once(
                    run_id="manual__changed-input",
                    spec_path=spec,
                    schema_path=schema,
                    output_root=outputs,
                    allowed_root=ROOT,
                )

    def test_tampered_report_is_not_reused(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            outputs = Path(directory) / "runs"
            first = self.execute(outputs, run_id="manual__tampered-report")
            report = outputs / first.run_key / "workflow-report.json"
            report.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(
                EvidenceWorkflowError,
                "report hash does not match",
            ):
                self.execute(outputs, run_id="manual__tampered-report")

    def test_distinct_run_ids_use_distinct_directories(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            outputs = Path(directory) / "runs"

            first = self.execute(outputs, run_id="manual__one")
            second = self.execute(outputs, run_id="manual__two")

            self.assertNotEqual(first.run_key, second.run_key)
            self.assertTrue((outputs / first.run_key / "run-manifest.json").is_file())
            self.assertTrue((outputs / second.run_key / "run-manifest.json").is_file())

    def test_output_root_cannot_leave_local_scope(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(EvidenceWorkflowError, "allowed_root"):
                self.execute(Path(outside))

    def test_run_directory_symlink_cannot_leave_local_scope(self) -> None:
        run_id = "manual__symlink"
        run_key = f"run-{hashlib.sha256(run_id.encode('utf-8')).hexdigest()[:24]}"
        with (
            tempfile.TemporaryDirectory(dir=ROOT) as directory,
            tempfile.TemporaryDirectory() as outside,
        ):
            outputs = Path(directory) / "runs"
            outputs.mkdir()
            (outputs / run_key).symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(EvidenceWorkflowError, "run_directory"):
                self.execute(outputs, run_id=run_id)

    def test_airflow_callable_uses_run_id_for_retry(self) -> None:
        module_spec = importlib.util.spec_from_file_location("retry_dag", DAG_PATH)
        self.assertIsNotNone(module_spec)
        self.assertIsNotNone(module_spec.loader)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            module.OUTPUT_ROOT = Path(directory) / "runs"
            first = module.persist_evidence("manual__airflow-fixture")
            second = module.persist_evidence("manual__airflow-fixture")

        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(first["run_key"], second["run_key"])


if __name__ == "__main__":
    unittest.main()
