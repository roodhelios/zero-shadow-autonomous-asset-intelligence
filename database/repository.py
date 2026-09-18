"""Transactional SQLite adapter for one complete asset evidence bundle."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from engine.correlation.asset_graph import ConsolidatedAsset
from engine.ownership import OwnershipResolution
from engine.remediation import RemediationPlan
from engine.risk import FindingEvidence


Scope = Literal["synthetic", "owned", "authorized"]
ALLOWED_SCOPES = {"synthetic", "owned", "authorized"}


class EvidenceRepositoryError(ValueError):
    """Raised when related evidence cannot be written without guessing."""


def _text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceRepositoryError(f"{field_name} must be a non-empty string")
    return value.strip()


def _timestamp(value: datetime, field_name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EvidenceRepositoryError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _observation_id(asset_id: str, source: str, source_record_id: str) -> str:
    material = "\x00".join((asset_id, source, source_record_id)).encode("utf-8")
    return f"observation-{hashlib.sha256(material).hexdigest()[:20]}"


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    asset: ConsolidatedAsset
    finding: FindingEvidence
    ownership: OwnershipResolution
    plan: RemediationPlan
    scope: Scope
    observed_at: datetime
    decision_id: str
    decided_at: datetime
    plan_id: str
    plan_version: int
    created_at: datetime

    def validate(self) -> None:
        if self.scope not in ALLOWED_SCOPES:
            raise EvidenceRepositoryError("scope must be synthetic, owned, or authorized")
        _text(self.asset.asset_id, "asset_id")
        _text(self.finding.finding_id, "finding_id")
        _text(self.decision_id, "decision_id")
        _text(self.plan_id, "plan_id")
        _timestamp(self.observed_at, "observed_at")
        _timestamp(self.decided_at, "decided_at")
        _timestamp(self.created_at, "created_at")
        if type(self.plan_version) is not int or self.plan_version < 1:
            raise EvidenceRepositoryError("plan_version must be a positive integer")
        if not self.asset.observations:
            raise EvidenceRepositoryError("asset must retain at least one observation")
        if self.finding.asset_id != self.asset.asset_id:
            raise EvidenceRepositoryError("finding asset_id must match the asset")
        if self.plan.asset_id != self.asset.asset_id:
            raise EvidenceRepositoryError("plan asset_id must match the asset")
        if self.plan.finding_id != self.finding.finding_id:
            raise EvidenceRepositoryError("plan finding_id must match the finding")
        if (
            self.plan.risk_assessment.asset_id != self.asset.asset_id
            or self.plan.risk_assessment.finding_id != self.finding.finding_id
        ):
            raise EvidenceRepositoryError("risk assessment must match the evidence bundle")
        if self.ownership.status == "resolved":
            if self.ownership.team_id is None or self.plan.owner != self.ownership.team_id:
                raise EvidenceRepositoryError(
                    "resolved ownership must match the remediation owner"
                )
        elif self.plan.owner is not None:
            raise EvidenceRepositoryError("unresolved ownership requires an unassigned plan")


@dataclass(frozen=True, slots=True)
class EvidenceWriteResult:
    asset_id: str
    observation_count: int
    finding_id: str
    decision_id: str
    plan_id: str
    plan_version: int


class EvidenceRepository:
    """Write linked evidence atomically through one supplied SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.execute("PRAGMA foreign_keys = ON")
        enabled = self.connection.execute("PRAGMA foreign_keys").fetchone()[0]
        if not enabled:
            raise EvidenceRepositoryError("SQLite foreign key enforcement is required")

    def store_bundle(self, bundle: EvidenceBundle) -> EvidenceWriteResult:
        bundle.validate()
        observed_at = _timestamp(bundle.observed_at, "observed_at")
        decided_at = _timestamp(bundle.decided_at, "decided_at")
        created_at = _timestamp(bundle.created_at, "created_at")
        asset = bundle.asset
        finding = bundle.finding
        ownership = bundle.ownership
        plan = bundle.plan

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO assets
                    (asset_id, kind_summary_json, primary_hostname, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    kind_summary_json = excluded.kind_summary_json,
                    primary_hostname = excluded.primary_hostname,
                    updated_at = excluded.updated_at
                """,
                (
                    asset.asset_id,
                    _json(list(asset.kinds)),
                    asset.hostnames[0] if asset.hostnames else None,
                    created_at,
                    created_at,
                ),
            )
            for observation in asset.observations:
                self.connection.execute(
                    """
                    INSERT INTO asset_observations
                        (observation_id, asset_id, source, source_record_id, scope,
                         observed_at, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        _observation_id(
                            asset.asset_id,
                            observation.source,
                            observation.source_record_id,
                        ),
                        asset.asset_id,
                        observation.source,
                        observation.source_record_id,
                        bundle.scope,
                        observed_at,
                        _json(observation.to_dict()),
                    ),
                )
            self.connection.execute(
                """
                INSERT INTO findings
                    (finding_id, asset_id, source, description, severity, exposure,
                     exploit_evidence, control_state, identity_confidence, evidence_json,
                     observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.asset_id,
                    finding.source,
                    finding.description,
                    finding.severity,
                    finding.exposure,
                    finding.exploit_evidence,
                    finding.control_state,
                    finding.identity_confidence,
                    _json(
                        {
                            "source": finding.source,
                            "description": finding.description,
                            "severity": finding.severity,
                            "exposure": finding.exposure,
                            "exploit_evidence": finding.exploit_evidence,
                            "control_state": finding.control_state,
                            "identity_confidence": finding.identity_confidence,
                        }
                    ),
                    observed_at,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO ownership_decisions
                    (decision_id, asset_id, status, team_id, matched_rule_ids_json,
                     candidate_team_ids_json, explanation, decided_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.decision_id,
                    asset.asset_id,
                    ownership.status,
                    ownership.team_id,
                    _json(list(ownership.matched_rule_ids)),
                    _json(list(ownership.candidate_team_ids)),
                    ownership.explanation,
                    decided_at,
                ),
            )
            factors = [
                {"kind": "risk", **factor.to_dict()}
                for factor in plan.risk_assessment.factors
            ] + [
                {"kind": "priority", **factor.to_dict()}
                for factor in plan.priority_factors
            ]
            self.connection.execute(
                """
                INSERT INTO remediation_plans
                    (plan_id, finding_id, plan_version, priority, owner_team_id,
                     opened_on, due_date, overdue, risk_score, risk_band, actions_json,
                     factors_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.plan_id,
                    finding.finding_id,
                    bundle.plan_version,
                    plan.priority,
                    plan.owner,
                    plan.opened_on.isoformat(),
                    plan.due_date.isoformat(),
                    int(plan.overdue),
                    plan.risk_assessment.score,
                    plan.risk_assessment.band,
                    _json(list(plan.actions)),
                    _json(factors),
                    created_at,
                ),
            )

        return EvidenceWriteResult(
            asset_id=asset.asset_id,
            observation_count=len(asset.observations),
            finding_id=finding.finding_id,
            decision_id=bundle.decision_id,
            plan_id=bundle.plan_id,
            plan_version=bundle.plan_version,
        )
