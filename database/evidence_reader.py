"""Read and verify one linked asset evidence snapshot from local SQLite."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping


class EvidenceReadError(ValueError):
    """Raised when stored evidence cannot be reconstructed without guessing."""


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceReadError(f"{field_name} must be a non-empty string")
    return value.strip()


def _json(value: Any, field_name: str, expected_type: type) -> Any:
    if not isinstance(value, str):
        raise EvidenceReadError(f"{field_name} must be stored as JSON text")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise EvidenceReadError(f"{field_name} is not valid JSON") from exc
    if not isinstance(parsed, expected_type):
        label = "object" if expected_type is dict else "array"
        raise EvidenceReadError(f"{field_name} must contain a JSON {label}")
    return parsed


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    asset: Mapping[str, Any]
    observations: tuple[Mapping[str, Any], ...]
    findings: tuple[Mapping[str, Any], ...]
    ownership_decisions: tuple[Mapping[str, Any], ...]
    remediation_plans: tuple[Mapping[str, Any], ...]
    snapshot_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "asset": dict(self.asset),
            "observations": [dict(item) for item in self.observations],
            "findings": [dict(item) for item in self.findings],
            "ownership_decisions": [
                dict(item) for item in self.ownership_decisions
            ],
            "remediation_plans": [dict(item) for item in self.remediation_plans],
            "snapshot_sha256": self.snapshot_sha256,
        }


class EvidenceReader:
    """Reconstruct one asset without changing the evidence database."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.execute("PRAGMA foreign_keys = ON")

    def read_asset(self, asset_id: str) -> EvidenceSnapshot:
        normalized_id = _text(asset_id, "asset_id")
        try:
            asset_row = self.connection.execute(
                """
                SELECT asset_id, kind_summary_json, primary_hostname,
                       created_at, updated_at
                FROM assets
                WHERE asset_id = ?
                """,
                (normalized_id,),
            ).fetchone()
            if asset_row is None:
                raise EvidenceReadError(f"asset was not found: {normalized_id}")
            asset = {
                "asset_id": asset_row[0],
                "kinds": _json(asset_row[1], "asset.kind_summary_json", list),
                "primary_hostname": asset_row[2],
                "created_at": asset_row[3],
                "updated_at": asset_row[4],
            }

            observations = self._observations(normalized_id)
            findings = self._findings(normalized_id)
            ownership = self._ownership(normalized_id)
            plans = self._plans(normalized_id)
        except EvidenceReadError:
            raise
        except sqlite3.DatabaseError as exc:
            raise EvidenceReadError("evidence database could not be read") from exc

        if not observations:
            raise EvidenceReadError("asset has no retained source observations")
        if not findings:
            raise EvidenceReadError("asset has no retained findings")
        if not ownership:
            raise EvidenceReadError("asset has no retained ownership decisions")
        finding_ids = {item["finding_id"] for item in findings}
        if not plans or any(item["finding_id"] not in finding_ids for item in plans):
            raise EvidenceReadError("asset remediation plans do not match its findings")

        body = {
            "schema_version": 1,
            "asset": asset,
            "observations": list(observations),
            "findings": list(findings),
            "ownership_decisions": list(ownership),
            "remediation_plans": list(plans),
        }
        digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        return EvidenceSnapshot(
            asset=asset,
            observations=observations,
            findings=findings,
            ownership_decisions=ownership,
            remediation_plans=plans,
            snapshot_sha256=digest,
        )

    def _observations(self, asset_id: str) -> tuple[Mapping[str, Any], ...]:
        rows = self.connection.execute(
            """
            SELECT observation_id, source, source_record_id, scope,
                   observed_at, payload_json
            FROM asset_observations
            WHERE asset_id = ?
            ORDER BY observed_at, observation_id
            """,
            (asset_id,),
        ).fetchall()
        values = []
        for row in rows:
            payload = _json(row[5], f"observation {row[0]}.payload_json", dict)
            if payload.get("source") != row[1]:
                raise EvidenceReadError(
                    f"observation {row[0]} source does not match its payload"
                )
            if payload.get("source_record_id") != row[2]:
                raise EvidenceReadError(
                    f"observation {row[0]} source_record_id does not match its payload"
                )
            values.append(
                {
                    "observation_id": row[0],
                    "source": row[1],
                    "source_record_id": row[2],
                    "scope": row[3],
                    "observed_at": row[4],
                    "payload": payload,
                }
            )
        return tuple(values)

    def _findings(self, asset_id: str) -> tuple[Mapping[str, Any], ...]:
        rows = self.connection.execute(
            """
            SELECT finding_id, source, description, severity, exposure,
                   exploit_evidence, control_state, identity_confidence,
                   evidence_json, observed_at
            FROM findings
            WHERE asset_id = ?
            ORDER BY observed_at, finding_id
            """,
            (asset_id,),
        ).fetchall()
        field_names = (
            "source",
            "description",
            "severity",
            "exposure",
            "exploit_evidence",
            "control_state",
            "identity_confidence",
        )
        values = []
        for row in rows:
            evidence = _json(row[8], f"finding {row[0]}.evidence_json", dict)
            expected = dict(zip(field_names, row[1:8]))
            if any(evidence.get(key) != value for key, value in expected.items()):
                raise EvidenceReadError(
                    f"finding {row[0]} columns do not match its evidence JSON"
                )
            values.append(
                {
                    "finding_id": row[0],
                    **expected,
                    "observed_at": row[9],
                    "evidence": evidence,
                }
            )
        return tuple(values)

    def _ownership(self, asset_id: str) -> tuple[Mapping[str, Any], ...]:
        rows = self.connection.execute(
            """
            SELECT decision_id, status, team_id, matched_rule_ids_json,
                   candidate_team_ids_json, explanation, decided_at
            FROM ownership_decisions
            WHERE asset_id = ?
            ORDER BY decided_at, decision_id
            """,
            (asset_id,),
        ).fetchall()
        return tuple(
            {
                "decision_id": row[0],
                "status": row[1],
                "team_id": row[2],
                "matched_rule_ids": _json(
                    row[3], f"ownership {row[0]}.matched_rule_ids_json", list
                ),
                "candidate_team_ids": _json(
                    row[4], f"ownership {row[0]}.candidate_team_ids_json", list
                ),
                "explanation": row[5],
                "decided_at": row[6],
            }
            for row in rows
        )

    def _plans(self, asset_id: str) -> tuple[Mapping[str, Any], ...]:
        rows = self.connection.execute(
            """
            SELECT p.plan_id, p.finding_id, p.plan_version, p.priority,
                   p.owner_team_id, p.opened_on, p.due_date, p.overdue,
                   p.risk_score, p.risk_band, p.actions_json, p.factors_json,
                   p.created_at
            FROM remediation_plans AS p
            JOIN findings AS f ON f.finding_id = p.finding_id
            WHERE f.asset_id = ?
            ORDER BY p.finding_id, p.plan_version, p.plan_id
            """,
            (asset_id,),
        ).fetchall()
        return tuple(
            {
                "plan_id": row[0],
                "finding_id": row[1],
                "plan_version": row[2],
                "priority": row[3],
                "owner_team_id": row[4],
                "opened_on": row[5],
                "due_date": row[6],
                "overdue": bool(row[7]),
                "risk_score": row[8],
                "risk_band": row[9],
                "actions": _json(row[10], f"plan {row[0]}.actions_json", list),
                "factors": _json(row[11], f"plan {row[0]}.factors_json", list),
                "created_at": row[12],
            }
            for row in rows
        )
