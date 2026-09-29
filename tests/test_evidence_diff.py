"""Tests for deterministic asset evidence snapshot comparison."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from database.evidence_diff import EvidenceDiffError, compare_snapshots
from database.evidence_diff_cli import main
from database.evidence_reader import EvidenceReader
from engine.evidence_workflow import load_workflow_spec, run_fixture_workflow


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "database" / "schema.sql"
SPEC_PATH = ROOT / "examples" / "workflow-spec.json"


def snapshot() -> dict:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        report = run_fixture_workflow(
            load_workflow_spec(SPEC_PATH, allowed_root=ROOT),
            connection=connection,
        )
        return EvidenceReader(connection).read_asset(report.asset_id).to_dict()
    finally:
        connection.close()


def resign(value: dict) -> dict:
    body = {key: item for key, item in value.items() if key != "snapshot_sha256"}
    encoded = json.dumps(
        body,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    value["snapshot_sha256"] = hashlib.sha256(encoded).hexdigest()
    return value


class EvidenceDiffTests(unittest.TestCase):
    def test_identical_snapshots_have_no_changes(self) -> None:
        value = snapshot()

        result = compare_snapshots(value, copy.deepcopy(value)).to_dict()

        self.assertFalse(result["changed"])
        self.assertEqual(result["asset_fields_changed"], [])
        self.assertEqual(result["findings"]["modified"], [])

    def test_reports_added_removed_modified_and_asset_fields(self) -> None:
        base = snapshot()
        current = copy.deepcopy(base)
        current["asset"]["updated_at"] = "2026-09-22T23:00:00Z"

        added = copy.deepcopy(current["observations"][0])
        added["observation_id"] = "observation-fixture-added"
        added["source_record_id"] = "source-fixture-added"
        added["payload"]["source_record_id"] = "source-fixture-added"
        current["observations"].append(added)

        current["findings"][0]["description"] = "Reviewed local finding"
        current["findings"][0]["evidence"]["description"] = "Reviewed local finding"
        removed_plan = current["remediation_plans"].pop()["plan_id"]
        resign(current)

        result = compare_snapshots(base, current).to_dict()

        self.assertTrue(result["changed"])
        self.assertEqual(result["asset_fields_changed"], ["updated_at"])
        self.assertEqual(
            result["observations"]["added"],
            ["observation-fixture-added"],
        )
        self.assertEqual(
            result["findings"]["modified"],
            [base["findings"][0]["finding_id"]],
        )
        self.assertEqual(result["remediation_plans"]["removed"], [removed_plan])

    def test_digest_tampering_is_rejected_before_comparison(self) -> None:
        base = snapshot()
        current = copy.deepcopy(base)
        current["asset"]["primary_hostname"] = "changed.example.test"

        with self.assertRaisesRegex(EvidenceDiffError, "integrity check"):
            compare_snapshots(base, current)

    def test_different_asset_identity_is_rejected(self) -> None:
        base = snapshot()
        current = copy.deepcopy(base)
        current["asset"]["asset_id"] = "asset-other"
        resign(current)

        with self.assertRaisesRegex(EvidenceDiffError, "same asset_id"):
            compare_snapshots(base, current)

    def test_duplicate_section_identifiers_are_rejected(self) -> None:
        base = snapshot()
        current = copy.deepcopy(base)
        current["findings"].append(copy.deepcopy(current["findings"][0]))
        resign(current)

        with self.assertRaisesRegex(EvidenceDiffError, "duplicate IDs"):
            compare_snapshots(base, current)

    def test_cli_writes_deterministic_diff(self) -> None:
        base = snapshot()
        current = copy.deepcopy(base)
        current["asset"]["updated_at"] = "2026-09-22T23:00:00Z"
        resign(current)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_path = root / "base.json"
            current_path = root / "current.json"
            output_path = root / "diff.json"
            base_path.write_text(json.dumps(base), encoding="utf-8")
            current_path.write_text(json.dumps(current), encoding="utf-8")

            status = main(
                [str(base_path), str(current_path), "--output", str(output_path)]
            )
            result = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertTrue(result["changed"])
        self.assertEqual(result["asset_fields_changed"], ["updated_at"])

    def test_cli_refuses_same_input_and_existing_output(self) -> None:
        value = snapshot()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "snapshot.json"
            source.write_text(json.dumps(value), encoding="utf-8")
            with redirect_stderr(errors):
                same_status = main([str(source), str(source)])

            current = root / "current.json"
            current.write_text(json.dumps(value), encoding="utf-8")
            existing = root / "diff.json"
            existing.write_text("keep", encoding="utf-8")
            with redirect_stderr(errors):
                overwrite_status = main(
                    [str(source), str(current), "--output", str(existing)]
                )

        self.assertEqual(same_status, 2)
        self.assertEqual(overwrite_status, 2)
        self.assertIn("must differ", errors.getvalue())
        self.assertIn("output already exists", errors.getvalue())

    def test_cli_can_render_to_stdout(self) -> None:
        value = snapshot()
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            current = root / "current.json"
            base.write_text(json.dumps(value), encoding="utf-8")
            current.write_text(json.dumps(value), encoding="utf-8")
            with redirect_stdout(output):
                status = main([str(base), str(current)])

        self.assertEqual(status, 0)
        self.assertFalse(json.loads(output.getvalue())["changed"])


if __name__ == "__main__":
    unittest.main()
