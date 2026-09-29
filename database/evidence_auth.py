"""Authenticate a snapshot manifest with a separately held HMAC key."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

from .evidence_diff import EvidenceDiffError, compare_snapshots


MANIFEST_FIELDS = {
    "schema_version", "algorithm", "key_id", "asset_id", "snapshot_sha256", "hmac_sha256"
}
DOMAIN = b"zero-shadow-evidence-manifest-v2\x00"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


class EvidenceAuthError(ValueError):
    """Raised when a snapshot or its authentication manifest cannot be trusted."""


def _key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise EvidenceAuthError("HMAC key must contain at least 32 bytes")
    return value


def _fields(value: Mapping[str, Any]) -> None:
    missing = sorted(MANIFEST_FIELDS - set(value))
    extra = sorted(set(value) - MANIFEST_FIELDS)
    if missing:
        raise EvidenceAuthError(f"manifest is missing fields: {', '.join(missing)}")
    if extra:
        raise EvidenceAuthError(f"manifest has unknown fields: {', '.join(extra)}")


def _key_id(value: str) -> str:
    if not isinstance(value, str) or not KEY_ID.fullmatch(value):
        raise EvidenceAuthError("key_id must be a lowercase identifier from 3 to 64 characters")
    return value


def _message(key_id: str, asset_id: str, digest: str) -> bytes:
    return (DOMAIN + key_id.encode("utf-8") + b"\x00" + asset_id.encode("utf-8")
            + b"\x00" + bytes.fromhex(digest))


def create_manifest(snapshot: Mapping[str, Any], key: bytes, *, key_id: str) -> dict[str, Any]:
    """Create an authentication manifest after validating the snapshot digest."""
    _key(key)
    normalized_key_id = _key_id(key_id)
    try:
        compare_snapshots(snapshot, snapshot)
    except EvidenceDiffError as exc:
        raise EvidenceAuthError(f"snapshot is invalid: {exc}") from exc
    asset_id = snapshot["asset"]["asset_id"].strip()
    digest = snapshot["snapshot_sha256"]
    mac = hmac.new(key, _message(normalized_key_id, asset_id, digest), hashlib.sha256).hexdigest()
    return {
        "schema_version": 2,
        "algorithm": "HMAC-SHA256",
        "key_id": normalized_key_id,
        "asset_id": asset_id,
        "snapshot_sha256": digest,
        "hmac_sha256": mac,
    }


def verify_manifest(
    snapshot: Mapping[str, Any], manifest: Mapping[str, Any], key: bytes, *, expected_key_id: str
) -> None:
    """Verify snapshot integrity and its separately retained HMAC manifest."""
    _key(key)
    if not isinstance(manifest, Mapping):
        raise EvidenceAuthError("manifest must be an object")
    _fields(manifest)
    normalized_key_id = _key_id(expected_key_id)
    if manifest["key_id"] != normalized_key_id:
        raise EvidenceAuthError("manifest key_id does not match the selected key")
    if not isinstance(manifest["hmac_sha256"], str) or not HEX_SHA256.fullmatch(
        manifest["hmac_sha256"]
    ):
        raise EvidenceAuthError("manifest hmac_sha256 must be lowercase SHA-256")
    expected = create_manifest(snapshot, key, key_id=normalized_key_id)
    if manifest["schema_version"] != 2 or manifest["algorithm"] != "HMAC-SHA256":
        raise EvidenceAuthError("manifest algorithm or schema version is unsupported")
    if not hmac.compare_digest(
        str(manifest["hmac_sha256"]), expected["hmac_sha256"]
    ):
        raise EvidenceAuthError("snapshot authentication failed")
    if manifest["asset_id"] != expected["asset_id"]:
        raise EvidenceAuthError("manifest asset_id does not match the snapshot")
    if manifest["snapshot_sha256"] != expected["snapshot_sha256"]:
        raise EvidenceAuthError("manifest digest does not match the snapshot")
