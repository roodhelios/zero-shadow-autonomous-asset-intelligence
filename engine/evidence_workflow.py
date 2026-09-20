"""Fixture-only evidence workflow with explicit review checkpoints."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping

from database.repository import EvidenceBundle, EvidenceRepository
from engine.correlation import correlate_assets
from engine.discovery import load_fixture
from engine.ownership import load_directory
from engine.remediation import plan_remediation
from engine.risk import FindingEvidence, score_finding


class EvidenceWorkflowError(ValueError):
    """Raised when the fixture workflow would need to guess or leave local scope."""


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceWorkflowError(f"{field_name} must be a non-empty string")
    return value.strip()


def _exact_fields(value: Mapping[str, Any], expected: set[str], field_name: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise EvidenceWorkflowError(f"{field_name} is missing fields: {', '.join(missing)}")
    if extra:
        raise EvidenceWorkflowError(f"{field_name} has unknown fields: {', '.join(extra)}")


def _local_path(
    value: Any,
    field_name: str,
    *,
    base: Path,
    allowed_root: Path,
) -> Path:
    text = _text(value, field_name)
    if "://" in text:
        raise EvidenceWorkflowError(f"{field_name} must be a local path")
    candidate = (base / text).resolve() if not Path(text).is_absolute() else Path(text).resolve()
    try:
        candidate.relative_to(allowed_root)
    except ValueError as exc:
        raise EvidenceWorkflowError(f"{field_name} must stay inside allowed_root") from exc
    return candidate


def _date(value: Any, field_name: str) -> date:
    try:
        return date.fromisoformat(_text(value, field_name))
    except ValueError as exc:
        raise EvidenceWorkflowError(f"{field_name} must use YYYY-MM-DD") from exc


def _timestamp(value: Any, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_text(value, field_name).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceWorkflowError(f"{field_name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceWorkflowError(f"{field_name} must include a UTC offset")
    return parsed


@dataclass(frozen=True, slots=True)
class WorkflowSpec:
    asset_fixture: Path
    ownership_directory: Path
    finding: Mapping[str, Any]
    opened_on: date
    as_of: date
    requested_due_date: date | None
    recorded_at: datetime
    decision_id: str
    plan_id: str
    plan_version: int


@dataclass(frozen=True, slots=True)
class WorkflowCheckpoint:
    checkpoint: str
    evidence: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"checkpoint": self.checkpoint, "evidence": dict(self.evidence)}


@dataclass(frozen=True, slots=True)
class WorkflowReport:
    asset_id: str
    finding_id: str
    decision_id: str
    plan_id: str
    checkpoints: tuple[WorkflowCheckpoint, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": "completed",
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "decision_id": self.decision_id,
            "plan_id": self.plan_id,
            "checkpoints": [item.to_dict() for item in self.checkpoints],
        }


FINDING_FIELDS = {
    "finding_id",
    "source",
    "description",
    "severity",
    "exposure",
    "exploit_evidence",
    "control_state",
    "identity_confidence",
}


def load_workflow_spec(
    path: str | Path,
    *,
    allowed_root: str | Path,
) -> WorkflowSpec:
    source = Path(path).resolve()
    root = Path(allowed_root).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise EvidenceWorkflowError("workflow spec must stay inside allowed_root") from exc
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceWorkflowError(f"cannot read workflow spec {source}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise EvidenceWorkflowError("workflow spec must be an object")
    expected = {
        "schema_version",
        "asset_fixture",
        "ownership_directory",
        "finding",
        "opened_on",
        "as_of",
        "requested_due_date",
        "recorded_at",
        "decision_id",
        "plan_id",
        "plan_version",
    }
    _exact_fields(value, expected, "workflow spec")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise EvidenceWorkflowError("schema_version must be 1")
    finding = value["finding"]
    if not isinstance(finding, Mapping):
        raise EvidenceWorkflowError("finding must be an object")
    _exact_fields(finding, FINDING_FIELDS, "finding")
    requested_due = value["requested_due_date"]
    plan_version = value["plan_version"]
    if type(plan_version) is not int or plan_version < 1:
        raise EvidenceWorkflowError("plan_version must be a positive integer")
    return WorkflowSpec(
        asset_fixture=_local_path(
            value["asset_fixture"],
            "asset_fixture",
            base=source.parent,
            allowed_root=root,
        ),
        ownership_directory=_local_path(
            value["ownership_directory"],
            "ownership_directory",
            base=source.parent,
            allowed_root=root,
        ),
        finding=dict(finding),
        opened_on=_date(value["opened_on"], "opened_on"),
        as_of=_date(value["as_of"], "as_of"),
        requested_due_date=(
            None
            if requested_due is None
            else _date(requested_due, "requested_due_date")
        ),
        recorded_at=_timestamp(value["recorded_at"], "recorded_at"),
        decision_id=_text(value["decision_id"], "decision_id"),
        plan_id=_text(value["plan_id"], "plan_id"),
        plan_version=plan_version,
    )


def _merged_tags(asset_observations: tuple[Any, ...]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for observation in asset_observations:
        for key, value in observation.tags.items():
            if key in tags and tags[key] != value:
                raise EvidenceWorkflowError(f"conflicting tag values for {key}")
            tags[key] = value
    return dict(sorted(tags.items()))


def run_fixture_workflow(
    spec: WorkflowSpec,
    *,
    connection: sqlite3.Connection,
) -> WorkflowReport:
    """Run one local fixture through correlation, scoring, planning, and storage."""

    batch = load_fixture(spec.asset_fixture)
    checkpoints = [
        WorkflowCheckpoint(
            "fixture_loaded",
            {
                "scope": batch.scope,
                "source": batch.source,
                "observation_count": len(batch.observations),
            },
        )
    ]
    assets = correlate_assets(batch.observations)
    if len(assets) != 1:
        raise EvidenceWorkflowError(
            "fixture workflow requires observations for exactly one correlated asset"
        )
    asset = assets[0]
    checkpoints.append(
        WorkflowCheckpoint(
            "asset_correlated",
            {"asset_id": asset.asset_id, "observation_count": len(asset.observations)},
        )
    )

    finding = FindingEvidence.from_dict({**spec.finding, "asset_id": asset.asset_id})
    assessment = score_finding(finding)
    checkpoints.append(
        WorkflowCheckpoint(
            "risk_scored",
            {"score": assessment.score, "band": assessment.band},
        )
    )

    ownership = load_directory(spec.ownership_directory).resolve(
        _merged_tags(asset.observations)
    )
    checkpoints.append(
        WorkflowCheckpoint(
            "ownership_resolved",
            {"status": ownership.status, "team_id": ownership.team_id},
        )
    )
    plan = plan_remediation(
        assessment,
        owner=ownership.team_id,
        opened_on=spec.opened_on,
        as_of=spec.as_of,
        requested_due_date=spec.requested_due_date,
    )
    checkpoints.append(
        WorkflowCheckpoint(
            "remediation_planned",
            {"priority": plan.priority, "due_date": plan.due_date.isoformat()},
        )
    )

    bundle = EvidenceBundle(
        asset=asset,
        finding=finding,
        ownership=ownership,
        plan=plan,
        scope=batch.scope,
        observed_at=spec.recorded_at,
        decision_id=spec.decision_id,
        decided_at=spec.recorded_at,
        plan_id=spec.plan_id,
        plan_version=spec.plan_version,
        created_at=spec.recorded_at,
    )
    result = EvidenceRepository(connection).store_bundle(bundle)
    checkpoints.append(
        WorkflowCheckpoint(
            "evidence_persisted",
            {
                "observation_count": result.observation_count,
                "plan_version": result.plan_version,
            },
        )
    )
    return WorkflowReport(
        asset_id=result.asset_id,
        finding_id=result.finding_id,
        decision_id=result.decision_id,
        plan_id=result.plan_id,
        checkpoints=tuple(checkpoints),
    )


def run_workflow_to_sqlite(
    *,
    spec_path: str | Path,
    schema_path: str | Path,
    database_path: str | Path,
    report_path: str | Path,
    allowed_root: str | Path,
) -> WorkflowReport:
    """Create new local outputs without overwriting evidence from an earlier run."""

    database = Path(database_path).resolve()
    report = Path(report_path).resolve()
    root = Path(allowed_root).resolve()
    for path, field_name in ((database, "database_path"), (report, "report_path")):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise EvidenceWorkflowError(f"{field_name} must stay inside allowed_root") from exc
        if path.exists():
            raise EvidenceWorkflowError(f"{field_name} already exists")
    if database == report:
        raise EvidenceWorkflowError("database_path and report_path must differ")

    spec = load_workflow_spec(spec_path, allowed_root=root)
    schema = Path(schema_path).resolve()
    try:
        schema.relative_to(root)
        sql = schema.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise EvidenceWorkflowError("schema_path must be a readable local file") from exc

    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    try:
        connection.executescript(sql)
        result = run_fixture_workflow(spec, connection=connection)
    except Exception:
        connection.close()
        database.unlink(missing_ok=True)
        raise
    connection.close()
    try:
        report.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except Exception:
        database.unlink(missing_ok=True)
        report.unlink(missing_ok=True)
        raise
    return result
