"""Deterministic remediation priorities with visible decision factors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Literal

from .risk import RiskAssessment


Priority = Literal["P0", "P1", "P2", "P3"]

BASE_PRIORITY = {"critical": 0, "high": 1, "moderate": 2, "low": 3}
SLA_DAYS = {"critical": 1, "high": 7, "moderate": 30, "low": 90}


@dataclass(frozen=True, slots=True)
class PriorityFactor:
    factor_id: str
    value: str
    priority_shift: int
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor_id": self.factor_id,
            "value": self.value,
            "priority_shift": self.priority_shift,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    finding_id: str
    asset_id: str
    priority: Priority
    owner: str | None
    opened_on: date
    due_date: date
    overdue: bool
    actions: tuple[str, ...]
    priority_factors: tuple[PriorityFactor, ...]
    risk_assessment: RiskAssessment

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "priority": self.priority,
            "owner": self.owner,
            "opened_on": self.opened_on.isoformat(),
            "due_date": self.due_date.isoformat(),
            "overdue": self.overdue,
            "actions": list(self.actions),
            "priority_factors": [factor.to_dict() for factor in self.priority_factors],
            "risk_assessment": self.risk_assessment.to_dict(),
        }


def _owner(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("owner must be a string or null")
    normalized = value.strip()
    return normalized or None


def plan_remediation(
    assessment: RiskAssessment,
    *,
    owner: str | None,
    opened_on: date,
    as_of: date,
    requested_due_date: date | None = None,
) -> RemediationPlan:
    """Create a reviewable priority without changing the technical risk score."""

    if not isinstance(opened_on, date) or not isinstance(as_of, date):
        raise ValueError("opened_on and as_of must be dates")
    if opened_on > as_of:
        raise ValueError("opened_on cannot be later than as_of")
    if requested_due_date is not None and not isinstance(requested_due_date, date):
        raise ValueError("requested_due_date must be a date or null")
    if requested_due_date is not None and requested_due_date < opened_on:
        raise ValueError("requested_due_date cannot be earlier than opened_on")

    normalized_owner = _owner(owner)
    sla_due_date = opened_on + timedelta(days=SLA_DAYS[assessment.band])
    due_date = (
        min(sla_due_date, requested_due_date)
        if requested_due_date is not None
        else sla_due_date
    )
    overdue = due_date < as_of

    factors = [
        PriorityFactor(
            "risk_band",
            assessment.band,
            0,
            f"Risk band starts at P{BASE_PRIORITY[assessment.band]}",
        )
    ]
    actions: list[str] = []
    shift = 0
    if normalized_owner is None:
        shift -= 1
        factors.append(
            PriorityFactor(
                "ownership",
                "unassigned",
                -1,
                "Missing ownership raises urgency by one level",
            )
        )
        actions.append("Assign an accountable owner")
    else:
        factors.append(
            PriorityFactor(
                "ownership",
                "assigned",
                0,
                "Assigned ownership does not change priority",
            )
        )

    if overdue:
        shift -= 1
        factors.append(
            PriorityFactor(
                "due_date",
                "overdue",
                -1,
                "An overdue item raises urgency by one level",
            )
        )
        actions.append("Escalate the overdue remediation for review")
    else:
        factors.append(
            PriorityFactor(
                "due_date",
                "within_window",
                0,
                "A current due date does not change priority",
            )
        )

    priority_number = max(0, min(3, BASE_PRIORITY[assessment.band] + shift))
    actions.append("Validate the finding evidence before changing the asset")
    return RemediationPlan(
        finding_id=assessment.finding_id,
        asset_id=assessment.asset_id,
        priority=f"P{priority_number}",
        owner=normalized_owner,
        opened_on=opened_on,
        due_date=due_date,
        overdue=overdue,
        actions=tuple(actions),
        priority_factors=tuple(factors),
        risk_assessment=assessment,
    )
