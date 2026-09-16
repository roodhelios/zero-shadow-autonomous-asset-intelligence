"""Tests for deterministic ownership resolution."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from engine.ownership import OwnershipDirectory, OwnershipError, load_directory


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY_PATH = ROOT / "examples" / "ownership-directory.json"


class OwnershipDirectoryTests(unittest.TestCase):
    def test_more_specific_rule_wins(self) -> None:
        directory = load_directory(DIRECTORY_PATH)

        result = directory.resolve(
            {"owner_group": "cloud-platform", "environment": "production"}
        )

        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.team_id, "cloud-platform")
        self.assertEqual(result.matched_rule_ids, ("production-cloud-platform",))

    def test_equal_rules_for_same_team_remain_resolved(self) -> None:
        directory = load_directory(DIRECTORY_PATH)

        result = directory.resolve({"service": "web", "exposure": "internet"})

        self.assertEqual(result.status, "resolved")
        self.assertEqual(result.team_id, "application-security")
        self.assertEqual(
            result.matched_rule_ids,
            ("internet-facing-review", "web-application"),
        )

    def test_equal_specificity_across_teams_is_ambiguous(self) -> None:
        directory = OwnershipDirectory.from_dict(
            {
                "schema_version": 1,
                "teams": [
                    {"team_id": "team-a", "display_name": "Team A"},
                    {"team_id": "team-b", "display_name": "Team B"},
                ],
                "rules": [
                    {
                        "rule_id": "environment-rule",
                        "team_id": "team-a",
                        "match_tags": {"environment": "production"},
                    },
                    {
                        "rule_id": "service-rule",
                        "team_id": "team-b",
                        "match_tags": {"service": "web"},
                    },
                ],
            }
        )

        result = directory.resolve({"environment": "production", "service": "web"})

        self.assertEqual(result.status, "ambiguous")
        self.assertIsNone(result.team_id)
        self.assertEqual(result.candidate_team_ids, ("team-a", "team-b"))

    def test_unmatched_tags_are_not_assigned(self) -> None:
        result = load_directory(DIRECTORY_PATH).resolve({"service": "batch"})

        self.assertEqual(result.status, "unmatched")
        self.assertIsNone(result.team_id)

    def test_rule_cannot_reference_unknown_team(self) -> None:
        value = json.loads(DIRECTORY_PATH.read_text(encoding="utf-8"))
        value["rules"][0]["team_id"] = "missing-team"

        with self.assertRaisesRegex(OwnershipError, "unknown team"):
            OwnershipDirectory.from_dict(value)


if __name__ == "__main__":
    unittest.main()
