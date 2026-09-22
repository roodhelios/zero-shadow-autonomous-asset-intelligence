"""Compare two verified local asset evidence snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_FIELDS = {
    "schema_version",
    "asset",
    "observations",
    "findings",
    "ownership_decisions",
    "remediation_plans",
    "snapshot_sha256",
}
SECTIONS = {
    "observations": "observation_id",
    "findings": "finding_id",
    "ownership_decisions": "decision_id",
    "remediation_plans": "plan_id",
}


class EvidenceDiffError(ValueError):
    """Raised when snapshots cannot be compared without guessing."""


def _canonical(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceDiffError("snapshot must contain finite JSON values") from exc


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceDiffError(f"{field_name} must be a non-empty string")
    return value.strip()


def _validate_snapshot(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceDiffError(f"{label} snapshot must be an object")
    missing = sorted(SNAPSHOT_FIELDS - set(value))
    extra = sorted(set(value) - SNAPSHOT_FIELDS)
    if missing:
        raise EvidenceDiffError(
            f"{label} snapshot is missing fields: {', '.join(missing)}"
        )
    if extra:
        raise EvidenceDiffError(
            f"{label} snapshot has unknown fields: {', '.join(extra)}"
        )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise EvidenceDiffError(f"{label} schema_version must be 1")
    asset = value["asset"]
    if not isinstance(asset, Mapping):
        raise EvidenceDiffError(f"{label} asset must be an object")
    _text(asset.get("asset_id"), f"{label} asset_id")

    for section, id_field in SECTIONS.items():
        items = value[section]
        if not isinstance(items, list):
            raise EvidenceDiffError(f"{label} {section} must be a list")
        identifiers = []
        for position, item in enumerate(items, start=1):
            if not isinstance(item, Mapping):
                raise EvidenceDiffError(
                    f"{label} {section} item {position} must be an object"
                )
            identifiers.append(
                _text(item.get(id_field), f"{label} {section}.{id_field}")
            )
        if len(identifiers) != len(set(identifiers)):
            raise EvidenceDiffError(f"{label} {section} contains duplicate IDs")

    digest = value["snapshot_sha256"]
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise EvidenceDiffError(f"{label} snapshot_sha256 must be lowercase SHA-256")
    body = {key: value[key] for key in SNAPSHOT_FIELDS if key != "snapshot_sha256"}
    expected = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    if digest != expected:
        raise EvidenceDiffError(f"{label} snapshot failed its SHA-256 integrity check")
    return value


def _section_changes(
    base: list[Mapping[str, Any]],
    current: list[Mapping[str, Any]],
    id_field: str,
) -> dict[str, list[str]]:
    base_by_id = {_text(item[id_field], id_field): item for item in base}
    current_by_id = {_text(item[id_field], id_field): item for item in current}
    shared = set(base_by_id) & set(current_by_id)
    return {
        "added": sorted(set(current_by_id) - set(base_by_id)),
        "removed": sorted(set(base_by_id) - set(current_by_id)),
        "modified": sorted(
            identifier
            for identifier in shared
            if _canonical(base_by_id[identifier]) != _canonical(current_by_id[identifier])
        ),
    }


@dataclass(frozen=True, slots=True)
class EvidenceDiff:
    asset_id: str
    base_snapshot_sha256: str
    current_snapshot_sha256: str
    asset_fields_changed: tuple[str, ...]
    section_changes: Mapping[str, Mapping[str, list[str]]]

    @property
    def changed(self) -> bool:
        return bool(self.asset_fields_changed) or any(
            values[kind]
            for values in self.section_changes.values()
            for kind in ("added", "removed", "modified")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "asset_id": self.asset_id,
            "base_snapshot_sha256": self.base_snapshot_sha256,
            "current_snapshot_sha256": self.current_snapshot_sha256,
            "changed": self.changed,
            "asset_fields_changed": list(self.asset_fields_changed),
            **{section: dict(changes) for section, changes in self.section_changes.items()},
        }


def compare_snapshots(base: Any, current: Any) -> EvidenceDiff:
    """Compare two digest-verified snapshots of the same asset."""

    base_value = _validate_snapshot(base, "base")
    current_value = _validate_snapshot(current, "current")
    base_asset = base_value["asset"]
    current_asset = current_value["asset"]
    asset_id = _text(base_asset["asset_id"], "base asset_id")
    if _text(current_asset["asset_id"], "current asset_id") != asset_id:
        raise EvidenceDiffError("snapshots must describe the same asset_id")
    asset_fields = sorted(
        field
        for field in set(base_asset) | set(current_asset)
        if field != "asset_id" and base_asset.get(field) != current_asset.get(field)
    )
    changes = {
        section: _section_changes(
            base_value[section],
            current_value[section],
            id_field,
        )
        for section, id_field in SECTIONS.items()
    }
    return EvidenceDiff(
        asset_id=asset_id,
        base_snapshot_sha256=base_value["snapshot_sha256"],
        current_snapshot_sha256=current_value["snapshot_sha256"],
        asset_fields_changed=tuple(asset_fields),
        section_changes=changes,
    )


def load_snapshot(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceDiffError(f"cannot read snapshot {path}") from exc
    if not isinstance(value, Mapping):
        raise EvidenceDiffError(f"snapshot {path} must be an object")
    return value
