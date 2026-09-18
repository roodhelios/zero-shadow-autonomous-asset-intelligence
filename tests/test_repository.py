"""Tests for transactional persistence of linked asset evidence."""

from __future__ import annotations

import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

from database.repository import (
    EvidenceBundle,
    EvidenceRepository,
    EvidenceRepositoryError,
)
from engine.correlation import correlate_assets
from engine.models import AssetObservation
from engine.ownership import OwnershipResolution
from engine.remediation import plan_remediation
from engine.risk import FindingEvidence, score_finding


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "database" / "schema.sql"
RECORDED_AT = datetime(2026, 9, 18, 23, 0, tzinfo=timezone.utc)


def make_bundle(
    record_id: str,
    *,
    finding_id: str | None = None,
    decision_id: str | None = None,
    plan_id: str | None = None,
) -> EvidenceBundle:
    observation = AssetObservation.from_dict(
        "cmdb-fixture",
        {
            "source_record_id": record_id,
            "kind": "server",
            "hostname": f"{record_id}.example.test",
            "ip_addresses": ["192.0.2.10"],
            "tags": {"team": "application-security"},
        },
    )
    asset = correlate_assets([observation])[0]
    evidence = FindingEvidence.from_dict(
        {
            "finding_id": finding_id or f"finding-{record_id}",
            "asset_id": asset.asset_id,
            "source": "scanner-fixture",
            "description": "Synthetic missing-control finding",
            "severity": "high",
            "exposure": "internet",
            "exploit_evidence": "none",
            "control_state": "missing",
            "identity_confidence": "high",
        }
    )
    assessment = score_finding(evidence)
    ownership = OwnershipResolution(
        status="resolved",
        team_id="application-security",
        matched_rule_ids=("rule-app-team",),
        candidate_team_ids=("application-security",),
        explanation="The fixture team tag selected one owner",
    )
    plan = plan_remediation(
        assessment,
        owner="application-security",
        opened_on=date(2026, 9, 18),
        as_of=date(2026, 9, 18),
    )
    return EvidenceBundle(
        asset=asset,
        finding=evidence,
        ownership=ownership,
        plan=plan,
        scope="synthetic",
        observed_at=RECORDED_AT,
        decision_id=decision_id or f"ownership-{record_id}",
        decided_at=RECORDED_AT,
        plan_id=plan_id or f"plan-{record_id}",
        plan_version=1,
        created_at=RECORDED_AT,
    )


class EvidenceRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.repository = EvidenceRepository(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def count(self, table: str) -> int:
        return self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_stores_one_complete_evidence_bundle(self) -> None:
        bundle = make_bundle("server-1")

        result = self.repository.store_bundle(bundle)

        self.assertEqual(result.asset_id, bundle.asset.asset_id)
        self.assertEqual(result.observation_count, 1)
        for table in (
            "assets",
            "asset_observations",
            "findings",
            "ownership_decisions",
            "remediation_plans",
        ):
            self.assertEqual(self.count(table), 1)

    def test_serialized_evidence_is_deterministic_and_reviewable(self) -> None:
        self.repository.store_bundle(make_bundle("server-1"))

        payload = self.connection.execute(
            "SELECT payload_json FROM asset_observations"
        ).fetchone()[0]
        factors = self.connection.execute(
            "SELECT factors_json FROM remediation_plans"
        ).fetchone()[0]

        self.assertEqual(json.loads(payload)["hostname"], "server-1.example.test")
        self.assertEqual(json.loads(factors)[0]["kind"], "risk")
        expected = json.dumps(
            json.loads(payload),
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(payload, expected)

    def test_late_constraint_failure_rolls_back_asset_and_observation(self) -> None:
        first = make_bundle("server-1", finding_id="finding-shared")
        second = make_bundle(
            "server-2",
            finding_id="finding-shared",
            decision_id="ownership-server-2",
            plan_id="plan-server-2",
        )
        self.repository.store_bundle(first)

        with self.assertRaises(sqlite3.IntegrityError):
            self.repository.store_bundle(second)

        self.assertEqual(self.count("assets"), 1)
        self.assertEqual(self.count("asset_observations"), 1)
        remaining_asset = self.connection.execute(
            "SELECT asset_id FROM assets"
        ).fetchone()[0]
        self.assertEqual(remaining_asset, first.asset.asset_id)

    def test_relationship_mismatch_is_rejected_before_writing(self) -> None:
        bundle = make_bundle("server-1")
        changed_finding = replace(bundle.finding, asset_id="asset-not-the-bundle")

        with self.assertRaisesRegex(EvidenceRepositoryError, "finding asset_id"):
            self.repository.store_bundle(replace(bundle, finding=changed_finding))

        self.assertEqual(self.count("assets"), 0)

    def test_resolved_owner_must_match_plan(self) -> None:
        bundle = make_bundle("server-1")
        mismatched = replace(bundle.plan, owner="cloud-platform")

        with self.assertRaisesRegex(EvidenceRepositoryError, "ownership"):
            self.repository.store_bundle(replace(bundle, plan=mismatched))

    def test_scope_and_timestamps_must_be_explicit(self) -> None:
        bundle = make_bundle("server-1")
        for changed, message in (
            (replace(bundle, scope="internet"), "scope must be"),
            (
                replace(bundle, observed_at=datetime(2026, 9, 18, 23, 0)),
                "timezone-aware",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(EvidenceRepositoryError, message):
                    self.repository.store_bundle(changed)


if __name__ == "__main__":
    unittest.main()
