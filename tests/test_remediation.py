"""Tests for deterministic remediation priority decisions."""

from __future__ import annotations

import io
import json
import unittest
from datetime import date

from engine.remediation import plan_remediation
from engine.remediation_cli import RemediationInputError, plan_jsonl
from engine.risk import FindingEvidence, score_finding


AS_OF = date(2026, 9, 15)


def assessment(**overrides: str):
    values = {
        "finding_id": "finding-1",
        "asset_id": "asset-example",
        "source": "synthetic-scanner",
        "description": "Synthetic service configuration finding",
        "severity": "medium",
        "exposure": "limited",
        "exploit_evidence": "none",
        "control_state": "unknown",
        "identity_confidence": "medium",
    }
    values.update(overrides)
    return score_finding(FindingEvidence.from_dict(values))


class RemediationPlanTests(unittest.TestCase):
    def test_critical_finding_has_one_day_target(self) -> None:
        plan = plan_remediation(
            assessment(severity="critical", exposure="internet"),
            owner="security-team",
            opened_on=AS_OF,
            as_of=AS_OF,
        )

        self.assertEqual(plan.priority, "P0")
        self.assertEqual(plan.due_date, date(2026, 9, 16))

    def test_missing_owner_raises_priority_one_level(self) -> None:
        plan = plan_remediation(
            assessment(),
            owner=None,
            opened_on=AS_OF,
            as_of=AS_OF,
        )

        self.assertEqual(plan.priority, "P1")
        self.assertIn("Assign an accountable owner", plan.actions)

    def test_overdue_item_raises_priority_one_level(self) -> None:
        plan = plan_remediation(
            assessment(),
            owner="platform-team",
            opened_on=date(2026, 7, 1),
            as_of=AS_OF,
        )

        self.assertTrue(plan.overdue)
        self.assertEqual(plan.priority, "P1")

    def test_later_requested_date_cannot_extend_risk_window(self) -> None:
        plan = plan_remediation(
            assessment(),
            owner="platform-team",
            opened_on=AS_OF,
            as_of=AS_OF,
            requested_due_date=date(2027, 1, 1),
        )

        self.assertEqual(plan.due_date, date(2026, 10, 15))

    def test_output_preserves_risk_and_priority_factors(self) -> None:
        output = plan_remediation(
            assessment(identity_confidence="low"),
            owner="platform-team",
            opened_on=AS_OF,
            as_of=AS_OF,
        ).to_dict()

        self.assertEqual(output["risk_assessment"]["identity_confidence"], "low")
        self.assertEqual(len(output["risk_assessment"]["factors"]), 4)
        self.assertEqual(len(output["priority_factors"]), 3)

    def test_rejects_future_open_date(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be later"):
            plan_remediation(
                assessment(),
                owner="platform-team",
                opened_on=date(2026, 9, 16),
                as_of=AS_OF,
            )

    def test_rejects_due_date_before_open_date(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be earlier"):
            plan_remediation(
                assessment(),
                owner="platform-team",
                opened_on=AS_OF,
                as_of=AS_OF,
                requested_due_date=date(2026, 9, 14),
            )


class RemediationJsonlTests(unittest.TestCase):
    def test_plans_fixture_record(self) -> None:
        record = {
            "finding": {
                "finding_id": "finding-1",
                "asset_id": "asset-example",
                "source": "synthetic-scanner",
                "description": "Synthetic configuration finding",
                "severity": "medium",
                "exposure": "limited",
                "exploit_evidence": "none",
                "control_state": "unknown",
                "identity_confidence": "high",
            },
            "owner": "platform-team",
            "opened_on": "2026-09-15",
        }
        destination = io.StringIO()

        emitted = plan_jsonl(
            io.StringIO(json.dumps(record) + "\n"),
            destination,
            as_of=AS_OF,
            source_name="fixture.jsonl",
        )

        self.assertEqual(emitted, 1)
        self.assertEqual(json.loads(destination.getvalue())["priority"], "P2")

    def test_reports_source_line_for_bad_date(self) -> None:
        record = {
            "finding": {
                "finding_id": "finding-1",
                "asset_id": "asset-example",
                "source": "synthetic-scanner",
                "description": "Synthetic configuration finding",
                "severity": "medium",
                "exposure": "limited",
                "exploit_evidence": "none",
                "control_state": "unknown",
                "identity_confidence": "high",
            },
            "opened_on": "not-a-date",
        }

        with self.assertRaisesRegex(RemediationInputError, "fixture.jsonl:1"):
            plan_jsonl(
                io.StringIO(json.dumps(record) + "\n"),
                io.StringIO(),
                as_of=AS_OF,
                source_name="fixture.jsonl",
            )


if __name__ == "__main__":
    unittest.main()
