"""Validate non-secret HMAC key lifecycle metadata for snapshot operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Literal


class EvidenceKeyringError(ValueError):
    """Raised when key lifecycle metadata does not authorize an operation."""


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceKeyringError(f"{field} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceKeyringError(f"{field} must be an ISO 8601 string") from exc
    if parsed.tzinfo is None:
        raise EvidenceKeyringError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def authorize_key_use(
    value: Mapping[str, Any], *, key_id: str,
    operation: Literal["create", "verify"], at: str,
) -> None:
    """Authorize create or verify from metadata that contains no key material."""
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "keys"}:
        raise EvidenceKeyringError("keyring must contain schema_version and keys")
    if value["schema_version"] != 1:
        raise EvidenceKeyringError("keyring schema_version must be 1")
    if operation not in {"create", "verify"}:
        raise EvidenceKeyringError("operation must be create or verify")
    keys = value["keys"]
    if not isinstance(keys, list) or not keys:
        raise EvidenceKeyringError("keyring keys must be a non-empty list")
    selected = None
    seen = set()
    for position, item in enumerate(keys, 1):
        if not isinstance(item, Mapping) or set(item) != {
            "key_id", "state", "activate_at", "verify_until"
        }:
            raise EvidenceKeyringError(f"key {position} has an unsupported shape")
        current_id = item["key_id"]
        if not isinstance(current_id, str) or current_id in seen:
            raise EvidenceKeyringError("key IDs must be unique strings")
        seen.add(current_id)
        if current_id == key_id:
            selected = item
    if selected is None:
        raise EvidenceKeyringError("selected key_id is not in the keyring")
    if selected["state"] not in {"active", "retired"}:
        raise EvidenceKeyringError("key state must be active or retired")
    current = _time(at, "at")
    activate = _time(selected["activate_at"], "activate_at")
    verify_until = _time(selected["verify_until"], "verify_until")
    if verify_until <= activate:
        raise EvidenceKeyringError("verify_until must be after activate_at")
    if current < activate or current >= verify_until:
        raise EvidenceKeyringError("selected key is outside its validity window")
    if operation == "create" and selected["state"] != "active":
        raise EvidenceKeyringError("only an active key can create a manifest")
