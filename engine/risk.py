"""Explainable risk scoring for fixture-backed asset findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping


Severity = Literal["low", "medium", "high", "critical"]
Exposure = Literal["internal", "limited", "internet"]
ExploitEvidence = Literal["none", "proof-of-concept", "observed"]
ControlState = Literal["effective", "unknown", "missing"]
Confidence = Literal["low", "medium", "high"]
RiskBand = Literal["low", "moderate", "high", "critical"]


class FindingValidationError(ValueError):
    """Raised when a finding cannot be scored without guessing."""


def _choice(value: Any, field_name: str, allowed: Mapping[str, int]) -> str:
    if not isinstance(value, str) or value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise FindingValidationError(f"{field_name} must be one of: {choices}")
    return value


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FindingValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 45, "critical": 60}
EXPOSURE_POINTS = {"internal": 0, "limited": 10, "internet": 20}
EXPLOIT_POINTS = {"none": 0, "proof-of-concept": 10, "observed": 20}
CONTROL_POINTS = {"effective": -15, "unknown": 0, "missing": 10}
IDENTITY_CONFIDENCE = {"low": 0, "medium": 0, "high": 0}


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """One observed or synthetic finding with explicit scoring inputs."""

    finding_id: str
    asset_id: str
    source: str
    description: str
    severity: Severity
    exposure: Exposure
    exploit_evidence: ExploitEvidence
    control_state: ControlState
    identity_confidence: Confidence

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FindingEvidence":
        if not isinstance(value, Mapping):
            raise FindingValidationError("finding must be an object")
        return cls(
            finding_id=_text(value.get("finding_id"), "finding_id"),
            asset_id=_text(value.get("asset_id"), "asset_id"),
            source=_text(value.get("source"), "source"),
            description=_text(value.get("description"), "description"),
            severity=_choice(value.get("severity"), "severity", SEVERITY_POINTS),
            exposure=_choice(value.get("exposure"), "exposure", EXPOSURE_POINTS),
            exploit_evidence=_choice(
                value.get("exploit_evidence"),
                "exploit_evidence",
                EXPLOIT_POINTS,
            ),
            control_state=_choice(
                value.get("control_state"),
                "control_state",
                CONTROL_POINTS,
            ),
            identity_confidence=_choice(
                value.get("identity_confidence"),
                "identity_confidence",
                IDENTITY_CONFIDENCE,
            ),
        )


@dataclass(frozen=True, slots=True)
class RiskFactor:
    factor_id: str
    value: str
    points: int
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor_id": self.factor_id,
            "value": self.value,
            "points": self.points,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    finding_id: str
    asset_id: str
    score: int
    band: RiskBand
    identity_confidence: Confidence
    factors: tuple[RiskFactor, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "score": self.score,
            "band": self.band,
            "identity_confidence": self.identity_confidence,
            "identity_confidence_scored": False,
            "factors": [factor.to_dict() for factor in self.factors],
        }


def _band(score: int) -> RiskBand:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def score_finding(finding: FindingEvidence) -> RiskAssessment:
    """Score one finding and preserve every contributing factor."""

    factors = (
        RiskFactor(
            "severity",
            finding.severity,
            SEVERITY_POINTS[finding.severity],
            "Reported technical impact of this finding",
        ),
        RiskFactor(
            "exposure",
            finding.exposure,
            EXPOSURE_POINTS[finding.exposure],
            "Reachability recorded by the fixture source",
        ),
        RiskFactor(
            "exploit_evidence",
            finding.exploit_evidence,
            EXPLOIT_POINTS[finding.exploit_evidence],
            "Evidence available for practical exploitability",
        ),
        RiskFactor(
            "control_state",
            finding.control_state,
            CONTROL_POINTS[finding.control_state],
            "Recorded state of a relevant compensating control",
        ),
    )
    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    return RiskAssessment(
        finding_id=finding.finding_id,
        asset_id=finding.asset_id,
        score=score,
        band=_band(score),
        identity_confidence=finding.identity_confidence,
        factors=factors,
    )
