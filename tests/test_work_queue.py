"""Tests for fixture-backed remediation work queues."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from engine.ownership import load_directory
from engine.work_queue_cli import WorkQueueInputError, build_from_jsonl, main


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY_PATH = ROOT / "examples" / "ownership-directory.json"
INPUT_PATH = ROOT / "examples" / "work-queue-input.jsonl"
AS_OF = date(2026, 9, 16)


class WorkQueueTests(unittest.TestCase):
    def test_groups_resolved_plans_and_preserves_unassigned(self) -> None:
        document = build_from_jsonl(
            INPUT_PATH,
            directory_path=DIRECTORY_PATH,
            as_of=AS_OF,
        )

        self.assertEqual(document["queue_count"], 2)
        self.assertEqual(document["assigned_item_count"], 2)
        self.assertEqual(document["unassigned_item_count"], 1)
        self.assertEqual(
            [queue["team_id"] for queue in document["queues"]],
            ["application-security", "cloud-platform"],
        )
        self.assertEqual(
            document["unassigned"][0]["ownership_resolution"]["status"],
            "unmatched",
        )
        self.assertIsNone(document["unassigned"][0]["owner"])

    def test_missing_owner_changes_priority_without_changing_risk(self) -> None:
        document = build_from_jsonl(
            INPUT_PATH,
            directory_path=DIRECTORY_PATH,
            as_of=AS_OF,
        )
        item = document["unassigned"][0]

        self.assertEqual(item["risk_assessment"]["band"], "low")
        self.assertEqual(item["priority"], "P2")
        self.assertEqual(item["priority_factors"][1]["value"], "unassigned")

    def test_cli_writes_versioned_queue_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "queues.json"
            status = main(
                [
                    str(INPUT_PATH),
                    "--directory",
                    str(DIRECTORY_PATH),
                    "--as-of",
                    AS_OF.isoformat(),
                    "--output",
                    str(output),
                ]
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(document["schema_version"], 1)

    def test_input_error_reports_source_line(self) -> None:
        record = {
            "asset_tags": {},
            "finding": {
                "finding_id": "finding-test",
                "asset_id": "asset-test",
                "source": "synthetic",
                "description": "Synthetic finding",
                "severity": "low",
                "exposure": "internal",
                "exploit_evidence": "none",
                "control_state": "effective",
                "identity_confidence": "high",
            },
            "opened_on": "not-a-date",
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.jsonl"
            source.write_text(json.dumps(record) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(WorkQueueInputError, "input.jsonl:1"):
                build_from_jsonl(
                    source,
                    directory_path=DIRECTORY_PATH,
                    as_of=AS_OF,
                )

    def test_directory_fixture_is_local_and_resolvable(self) -> None:
        directory = load_directory(DIRECTORY_PATH)

        self.assertEqual(len(directory.teams), 2)
        self.assertEqual(len(directory.rules), 4)


if __name__ == "__main__":
    unittest.main()
