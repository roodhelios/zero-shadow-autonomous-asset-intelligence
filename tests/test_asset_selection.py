"""A finding binds to one explicitly reviewed identity in a multi-asset batch."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from engine.correlation import correlate_assets
from engine.discovery import load_fixture
from engine.evidence_workflow import load_workflow_spec, run_fixture_workflow, EvidenceWorkflowError
from engine.workflow_runs import run_workflow_once

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "database/schema.sql"


class AssetSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "examples")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        fixture = json.loads((ROOT / "examples/workflow-selection-assets.json").read_text())
        self.fixture = self.root / "assets.json"
        self.fixture.write_text(json.dumps(fixture))
        assets = correlate_assets(load_fixture(self.fixture).observations)
        self.selected = next(a for a in assets if "checkout.example.test" in a.hostnames).asset_id
        self.other = next(a for a in assets if a.asset_id != self.selected).asset_id
        self.value = json.loads((ROOT / "examples/workflow-spec.json").read_text())
        self.value.update(asset_fixture="assets.json", ownership_directory="../ownership-directory.json")
        self.spec = self.root / "spec.json"

    def write_spec(self):
        self.spec.write_text(json.dumps(self.value))
        return load_workflow_spec(self.spec, allowed_root=ROOT)

    def run_spec(self):
        spec = self.write_spec()
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript(SCHEMA.read_text())
        return run_fixture_workflow(spec, connection=connection), connection

    def test_selection_persists_only_the_selected_identity_and_reports_exclusions(self):
        self.value["asset_id"] = self.selected
        report, connection = self.run_spec()
        self.assertEqual(report.asset_id, self.selected)
        self.assertEqual(connection.execute("SELECT asset_id FROM assets").fetchall(), [(self.selected,)])
        self.assertEqual(connection.execute("SELECT asset_id FROM findings").fetchall(), [(self.selected,)])
        stage = report.to_dict()["checkpoints"][1]["evidence"]
        self.assertEqual((stage["batch_asset_count"], stage["excluded_asset_count"], stage["selection"]), (2, 1, "explicit"))
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM asset_observations").fetchone()[0], 1)

    def test_ambiguous_batch_and_unknown_selection_fail_before_storage(self):
        for selection in (None, "asset-not-present"):
            if selection is not None:
                self.value["asset_id"] = selection
            with self.assertRaises(EvidenceWorkflowError):
                self.run_spec()

    def test_invalid_selector_and_unrelated_unknown_fields_fail(self):
        for selector in (None, 3, [], " "):
            self.value["asset_id"] = selector
            with self.assertRaises(EvidenceWorkflowError):
                self.write_spec()
        self.value["asset_id"] = self.selected
        self.value["guess_target"] = True
        with self.assertRaises(EvidenceWorkflowError):
            self.write_spec()

    def test_completed_run_reuses_same_selection_and_rejects_changed_target(self):
        self.value["asset_id"] = self.selected
        self.write_spec()
        args = dict(run_id="selection-test", spec_path=self.spec, schema_path=SCHEMA,
                    output_root=self.root / "runs", allowed_root=ROOT)
        first = run_workflow_once(**args)
        self.assertFalse(first.reused)
        self.assertTrue(run_workflow_once(**args).reused)
        self.value["asset_id"] = self.other
        self.write_spec()
        with self.assertRaises(EvidenceWorkflowError):
            run_workflow_once(**args)


if __name__ == "__main__":
    unittest.main()
