"""Load asset observations from local JSON fixtures with explicit scope."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from engine.models import AssetObservation, AssetValidationError


ALLOWED_SCOPES = {"synthetic", "owned", "authorized"}


@dataclass(frozen=True, slots=True)
class FixtureBatch:
    source: str
    scope: str
    observations: tuple[AssetObservation, ...]


def load_fixture(path: str | Path) -> FixtureBatch:
    """Load one local fixture. This function never performs network discovery."""

    fixture_path = Path(path)
    try:
        raw: Any = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetValidationError(f"cannot read fixture {fixture_path}: {exc}") from exc

    if not isinstance(raw, Mapping):
        raise AssetValidationError("fixture root must be an object")
    if raw.get("schema_version") != 1:
        raise AssetValidationError("schema_version must be 1")

    source = raw.get("source")
    if not isinstance(source, str) or not source.strip():
        raise AssetValidationError("source must be a non-empty string")

    scope = raw.get("scope")
    if scope not in ALLOWED_SCOPES:
        allowed = ", ".join(sorted(ALLOWED_SCOPES))
        raise AssetValidationError(f"scope must be one of: {allowed}")

    assets = raw.get("assets")
    if not isinstance(assets, list):
        raise AssetValidationError("assets must be a list")

    observations = tuple(AssetObservation.from_dict(source, item) for item in assets)
    return FixtureBatch(source=source.strip().lower(), scope=scope, observations=observations)
