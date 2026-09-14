"""Boundary tests for explainable fixture-backed risk scoring."""

from __future__ import annotations

import unittest

from engine.risk import FindingEvidence, FindingValidationError, score_finding


def finding(**overrides: str) -> FindingEvidence:
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
    return FindingEvidence.from_dict(values)


class RiskScoringTests(unittest.TestCase):
    def test_explains_every_scored_factor(self) -> None:
        assessment = score_finding(finding())

        self.assertEqual(assessment.score, 35)
        self.assertEqual(assessment.band, "moderate")
        self.assertEqual(
            [factor.factor_id for factor in assessment.factors],
            ["severity", "exposure", "exploit_evidence", "control_state"],
        )

    def test_clamps_highest_combination_to_100(self) -> None:
        assessment = score_finding(
            finding(
                severity="critical",
                exposure="internet",
                exploit_evidence="observed",
                control_state="missing",
            )
        )

        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.band, "critical")

    def test_effective_control_cannot_produce_negative_score(self) -> None:
        assessment = score_finding(
            finding(
                severity="low",
                exposure="internal",
                exploit_evidence="none",
                control_state="effective",
            )
        )

        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.band, "low")

    def test_identity_confidence_does_not_change_risk_score(self) -> None:
        low = score_finding(finding(identity_confidence="low"))
        high = score_finding(finding(identity_confidence="high"))

        self.assertEqual(low.score, high.score)
        self.assertFalse(low.to_dict()["identity_confidence_scored"])

    def test_rejects_unknown_scoring_value(self) -> None:
        with self.assertRaisesRegex(FindingValidationError, "severity must be"):
            finding(severity="urgent")

    def test_output_is_deterministic(self) -> None:
        first = score_finding(finding()).to_dict()
        second = score_finding(finding()).to_dict()

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
