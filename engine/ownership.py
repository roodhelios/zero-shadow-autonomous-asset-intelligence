"""Fixture-backed ownership resolution with explicit ambiguity handling."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping


ResolutionStatus = Literal["resolved", "unmatched", "ambiguous"]


class OwnershipError(ValueError):
    """Raised when an ownership directory cannot be used without guessing."""


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OwnershipError(f"{field_name} must be a non-empty string")
    return value.strip()


def _tag_map(value: Any, field_name: str, *, allow_empty: bool) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise OwnershipError(f"{field_name} must be an object")
    tags: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _text(key, f"{field_name} key").lower()
        if normalized_key in tags:
            raise OwnershipError(f"{field_name} contains duplicate key: {normalized_key}")
        tags[normalized_key] = _text(item, f"{field_name}.{normalized_key}")
    if not tags and not allow_empty:
        raise OwnershipError(f"{field_name} must not be empty")
    return MappingProxyType(dict(sorted(tags.items())))


@dataclass(frozen=True, slots=True)
class Team:
    team_id: str
    display_name: str


@dataclass(frozen=True, slots=True)
class OwnershipRule:
    rule_id: str
    team_id: str
    match_tags: Mapping[str, str]

    @property
    def specificity(self) -> int:
        return len(self.match_tags)

    def matches(self, tags: Mapping[str, str]) -> bool:
        return all(tags.get(key) == value for key, value in self.match_tags.items())


@dataclass(frozen=True, slots=True)
class OwnershipResolution:
    status: ResolutionStatus
    team_id: str | None
    matched_rule_ids: tuple[str, ...]
    candidate_team_ids: tuple[str, ...]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "team_id": self.team_id,
            "matched_rule_ids": list(self.matched_rule_ids),
            "candidate_team_ids": list(self.candidate_team_ids),
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class OwnershipDirectory:
    teams: Mapping[str, Team]
    rules: tuple[OwnershipRule, ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OwnershipDirectory":
        if not isinstance(value, Mapping):
            raise OwnershipError("directory must be an object")
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise OwnershipError("schema_version must be 1")

        raw_teams = value.get("teams")
        if not isinstance(raw_teams, list) or not raw_teams:
            raise OwnershipError("teams must be a non-empty list")
        teams: dict[str, Team] = {}
        for raw_team in raw_teams:
            if not isinstance(raw_team, Mapping):
                raise OwnershipError("team must be an object")
            team_id = _text(raw_team.get("team_id"), "team_id")
            if team_id in teams:
                raise OwnershipError(f"duplicate team_id: {team_id}")
            teams[team_id] = Team(
                team_id=team_id,
                display_name=_text(raw_team.get("display_name"), "display_name"),
            )

        raw_rules = value.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise OwnershipError("rules must be a non-empty list")
        rule_ids: set[str] = set()
        rules: list[OwnershipRule] = []
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, Mapping):
                raise OwnershipError("rule must be an object")
            rule_id = _text(raw_rule.get("rule_id"), "rule_id")
            team_id = _text(raw_rule.get("team_id"), f"{rule_id}.team_id")
            if rule_id in rule_ids:
                raise OwnershipError(f"duplicate rule_id: {rule_id}")
            if team_id not in teams:
                raise OwnershipError(f"{rule_id} references unknown team: {team_id}")
            rule_ids.add(rule_id)
            rules.append(
                OwnershipRule(
                    rule_id=rule_id,
                    team_id=team_id,
                    match_tags=_tag_map(
                        raw_rule.get("match_tags"),
                        f"{rule_id}.match_tags",
                        allow_empty=False,
                    ),
                )
            )

        return cls(
            teams=MappingProxyType(dict(sorted(teams.items()))),
            rules=tuple(sorted(rules, key=lambda rule: rule.rule_id)),
        )

    def resolve(self, tags: Mapping[str, str]) -> OwnershipResolution:
        """Choose the most specific rule, but never guess across tied teams."""

        normalized_tags = _tag_map(tags, "asset_tags", allow_empty=True)
        matches = tuple(rule for rule in self.rules if rule.matches(normalized_tags))
        if not matches:
            return OwnershipResolution(
                status="unmatched",
                team_id=None,
                matched_rule_ids=(),
                candidate_team_ids=(),
                explanation="No ownership rule matched the supplied asset tags",
            )

        specificity = max(rule.specificity for rule in matches)
        strongest = tuple(rule for rule in matches if rule.specificity == specificity)
        candidate_teams = tuple(sorted({rule.team_id for rule in strongest}))
        matched_rule_ids = tuple(sorted(rule.rule_id for rule in strongest))
        if len(candidate_teams) > 1:
            return OwnershipResolution(
                status="ambiguous",
                team_id=None,
                matched_rule_ids=matched_rule_ids,
                candidate_team_ids=candidate_teams,
                explanation="Equally specific ownership rules point to different teams",
            )

        return OwnershipResolution(
            status="resolved",
            team_id=candidate_teams[0],
            matched_rule_ids=matched_rule_ids,
            candidate_team_ids=candidate_teams,
            explanation="The most specific matching ownership rule selected one team",
        )


def load_directory(path: str | Path) -> OwnershipDirectory:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OwnershipError(f"{source}: invalid JSON ({exc.msg})") from exc
    return OwnershipDirectory.from_dict(value)
